from database import engine, SessionLocal
from models import Base, GoldenBaseline, ClusterTopology

Base.metadata.create_all(bind=engine)
db = SessionLocal()

if not db.query(GoldenBaseline).first():
    app_a_config = {
        "db_cfg": {
            "maxappls": "AUTOMATIC", "autorestart": "ON", "archretrydelay": "20",
            "num_db_backups": "14", "numarchretry": "5", "connect_proc": None,
            "logprimary": "100", "logsecond": "20", "logfilsiz": "16384",
            "logarchmeth1": "DISK:/home/db2inst1/archlogs", "trackmod": "ON", "locktimeout": "15"
        },
        "dbm_cfg": {
            "diaglevel": "3", "notifylevel": "3", "authentication": "SERVER_ENCRYPT",
            "catalog_noauth": "NO", "max_connections": "2000", "max_coordagents": "AUTOMATIC",
            "srvcon_auth": "SERVER_ENCRYPT", "trust_allclnts": "YES", "trust_clntauth": "CLIENT", "audit_buf_sz": "1000"
        }
    }
    app_b_config = {
        "db_cfg": {
            "maxappls": "AUTOMATIC", "autorestart": "ON", "archretrydelay": "20",
            "num_db_backups": "7", "numarchretry": "5", "connect_proc": None,
            "logprimary": "20", "logsecond": "150", "logfilsiz": "8192",
            "logarchmeth1": "DISK:/home/db2inst1/archlogs", "trackmod": "ON", "locktimeout": "60", "util_heap_sz": "50000"
        },
        "dbm_cfg": {
            "diaglevel": "3", "notifylevel": "3", "authentication": "SERVER_ENCRYPT",
            "catalog_noauth": "NO", "max_connections": "500", "max_coordagents": "200",
            "srvcon_auth": "SERVER_ENCRYPT", "trust_allclnts": "YES", "trust_clntauth": "CLIENT", "audit_buf_sz": "0"
        }
    }
    base_a = GoldenBaseline(name="PAYMENT_APP_BASELINE_V1", parameters=app_a_config)
    base_b = GoldenBaseline(name="INSURANCE_APP_BASELINE_V1", parameters=app_b_config)
    db.add_all([base_a, base_b])
    db.commit()

    cluster_a = ClusterTopology(
        app_name="App A", db_name="KYDB2A", primary_ip="10.10.1.4", standby_ip="10.10.1.5", port=50000,
        app_criticality="Tier 1", maintenance_window="00:00 - 04:00", app_group="PaymentOPS", dba_group="DB2OPS",
        baseline_id=base_a.id
    )
    cluster_b = ClusterTopology(
        app_name="App B", db_name="KYDB2B", primary_ip="10.10.2.4", standby_ip="10.10.2.5", port=50000,
        app_criticality="Tier 2", maintenance_window="02:00 - 06:00", app_group="InsuranceOPS", dba_group="DB2OPS",
        baseline_id=base_b.id
    )
    db.add_all([cluster_a, cluster_b])
    db.commit()
    print("PostgreSQL successfully initialized and seeded with Golden Baselines & Topologies.")
else:
    print("PostgreSQL already contains baseline configuration data.")

db.close()
