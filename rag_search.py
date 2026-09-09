"""
Fetches relevant DB2 documentation excerpts from Azure AI Search using
exact OData matching with a 1536-dimension hybrid vector fallback.

Called with a short, pre-filtered list of parameter names (see
_extract_drifted_param_names in app.py) rather than every parameter in a
scan, to keep both the number of Search/embedding calls and the resulting
prompt token count proportional to what actually looks drifted.

Safe to import even before AZURE_SEARCH_* / AZURE_OPENAI_* are configured —
get_db2_documentation() just returns "" in that case, so build_system_prompt()
falls back to running without a documentation section rather than the whole
app failing to start.
"""
import os
from typing import List, Optional

from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.search.documents.models import VectorizedQuery
from openai import AzureOpenAI

SEARCH_ENDPOINT = os.getenv("AZURE_SEARCH_ENDPOINT")
SEARCH_API_KEY = os.getenv("AZURE_SEARCH_API_KEY")
INDEX_NAME = os.getenv("AZURE_SEARCH_INDEX_NAME")

AOAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
AOAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
AOAI_EMBEDDING_DEPLOYMENT = os.getenv("AZURE_OPENAI_EMBEDDING_DEPLOYMENT", "text-embedding-3-small")
AOAI_EMBEDDING_DIMENSIONS = 1536

_search_client: Optional[SearchClient] = None
_aoai_client: Optional[AzureOpenAI] = None

if SEARCH_ENDPOINT and SEARCH_API_KEY and INDEX_NAME:
    try:
        _search_client = SearchClient(
            endpoint=SEARCH_ENDPOINT,
            index_name=INDEX_NAME,
            credential=AzureKeyCredential(SEARCH_API_KEY),
        )
    except Exception as ex:
        print(f"[RAG SEARCH INIT ERROR]: {ex}")
        _search_client = None

if AOAI_ENDPOINT and AOAI_API_KEY and AOAI_EMBEDDING_DEPLOYMENT:
    try:
        _aoai_client = AzureOpenAI(
            azure_endpoint=AOAI_ENDPOINT,
            api_key=AOAI_API_KEY,
            api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-05-01-preview"),
        )
    except Exception as ex:
        print(f"[AOAI INIT ERROR]: {ex}")
        _aoai_client = None


def _get_embedding(text: str) -> Optional[List[float]]:
    """Generates a 1536-dimension query embedding. Returns None on any
    failure so callers can fall back to keyword-only search."""
    if not _aoai_client:
        return None
    try:
        response = _aoai_client.embeddings.create(
            model=AOAI_EMBEDDING_DEPLOYMENT,
            input=[text],
            dimensions=AOAI_EMBEDDING_DIMENSIONS,
        )
        return response.data[0].embedding
    except Exception as ex:
        print(f"[EMBEDDING ERROR]: {ex}")
        return None


def get_db2_documentation(parameter_names: List[str]) -> str:
    """
    Fetches official IBM Db2 12.1 documentation for the given parameter
    names (expected to already be pre-filtered to a small, likely-drifted
    set — see app.py). Prioritises a deterministic exact-match OData filter
    lookup per parameter, falling back to hybrid keyword + vector search
    when no exact match exists.
    """
    if not _search_client or not parameter_names:
        return ""

    excerpts = []

    for param in parameter_names:
        clean_param = param.strip().lower()
        safe_param = clean_param.replace("'", "''")  # escape OData string literal
        doc = None

        try:
            # 1. Exact parameter lookup (OData filter) — cheap and deterministic.
            results = list(
                _search_client.search(
                    search_text="*",
                    filter=f"parameter_name eq '{safe_param.upper()}' or parameter_name eq '{safe_param}'",
                    top=1,
                )
            )

            if results:
                doc = results[0]
            else:
                # 2. Hybrid fallback (keyword + 1536-dim vector search).

                query_vector = _get_embedding(f"Db2 configuration parameter {clean_param}")
                search_kwargs = {
                    "search_text": f'"{clean_param}" "configuration parameter"',
                    "top": 1,
                }

                if query_vector:
                    search_kwargs["vector_queries"] = [
                        VectorizedQuery(
                            vector=query_vector,
                            k_nearest_neighbors=3,
                            fields="content_vector",
                        )
                    ]

                fallback_results = list(_search_client.search(**search_kwargs))
                if fallback_results:
                    doc = fallback_results[0]

        except Exception as ex:
            # Previously this just `continue`d — silently dropping the
            # parameter with no trace beyond a print() that never reaches
            # the response. Keep the print (check `journalctl -u
            # db2agentic` or your server log for the real exception text —
            # that's what tells you whether this is a field-name mismatch,
            # a missing parameter_name column, or something else), but
            # also surface a clearly-labelled entry so a lookup failure is
            # visibly different from "not found in index" and doesn't
            # silently vanish from the AI's context.
            print(f"[RAG SEARCH ERROR for {clean_param}]: {ex}")
            excerpts.append(
                f"PARAMETER: {clean_param.upper()}\n"
                f"CONFIGURABLE ONLINE: Unknown\n"
                f"DOCUMENTED PERFORMANCE IMPACT: Unknown\n"
                f"DESCRIPTION: Documentation lookup failed for this parameter "
                f"(search error) — see server logs. Not the same as 'not found'."
            )
            continue

        if doc:
          # Check every possible text field name
          content = (
              doc.get("full_text")
              or doc.get("content")
              or doc.get("chunk")
              or doc.get("text")
              or ""
          ).strip()

          param_type = doc.get("parameter_type") or "Database"
          perf_impact = doc.get("performance_impact") or "Unknown"

          # Handle configurable_online strictly
          raw_online = doc.get("configurable_online")
          if isinstance(raw_online, bool):
            online_str = "Yes" if raw_online else "No"
          elif isinstance(raw_online, str) and raw_online.strip():
            val = raw_online.strip().lower()
            if "yes" in val or "immediate" in val:
              online_str = "Yes"
            elif "no" in val or "deferred" in val:
              online_str = "No"
            else:
              online_str = "Unknown"
          else:
            online_str = "Unknown"

          entry = (
              f"PARAMETER: {clean_param.upper()}\n"
              f"TYPE: {param_type}\n"
              f"CONFIGURABLE ONLINE: {online_str}\n"
              f"DOCUMENTED PERFORMANCE IMPACT: {perf_impact}\n"
              f"DESCRIPTION: {content}"
          )
          excerpts.append(entry)
        else:
            excerpts.append(
                f"PARAMETER: {clean_param.upper()}\n"
                f"CONFIGURABLE ONLINE: Unknown\n"
                f"DOCUMENTED PERFORMANCE IMPACT: Unknown\n"
                f"DESCRIPTION: Parameter metadata not found in documentation index."
            )
    hits = sum(1 for e in excerpts if "DESCRIPTION: Parameter metadata not found" not in e and "DESCRIPTION: Documentation lookup failed" not in e)
    print(f"[RAG SUMMARY] {hits}/{len(parameter_names)} parameters resolved from the documentation index.")

    if not excerpts:
        return ""

    return (
        "=== START OFFICIAL IBM DB2 DOCUMENTATION ===\n\n"
        + "\n\n--------------------------------------------\n\n".join(excerpts)
        + "\n\n=== END OFFICIAL IBM DB2 DOCUMENTATION ==="
    )