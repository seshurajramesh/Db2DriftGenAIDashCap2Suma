from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base


class GoldenBaseline(Base):
    __tablename__ = 'golden_baselines'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    parameters = Column(JSONB, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    clusters = relationship("ClusterTopology", back_populates="baseline")


class ClusterTopology(Base):
    __tablename__ = 'cluster_topology'
    id = Column(Integer, primary_key=True, index=True)
    app_name = Column(String(50), unique=True, nullable=False)
    db_name = Column(String(50), nullable=False)
    primary_ip = Column(String(15), nullable=False)
    standby_ip = Column(String(15), nullable=False)
    port = Column(Integer, default=50000)
    app_criticality = Column(String(20), default="Tier 1")
    maintenance_window = Column(String(50), default="00:00 - 04:00")
    app_group = Column(String(50), default="AppOPS")
    dba_group = Column(String(50), default="DB2OPS")
    baseline_id = Column(Integer, ForeignKey('golden_baselines.id'))
    baseline = relationship("GoldenBaseline", back_populates="clusters")


class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String(50), nullable=False)   # DRIFT_SCAN | HITL_EXECUTION | LOG_ANALYSIS
    cluster_app = Column(String(50))
    node_ip = Column(String(15))
    overall_risk = Column(String(20))
    executed_command = Column(Text)
    ai_rca = Column(Text)
    status = Column(String(20))
    actor = Column(String(100))  # identity of whoever authorized/executed the action
    raw_payload = Column(JSONB)
