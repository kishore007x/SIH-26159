import logging
import numpy as np
import joblib
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.app.analysis.crypto_analyzer import SessionAnalysis, CryptoAnalyzer
from backend.app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class AnomalyResult:
    session_id: int
    stream_id: int
    anomaly_score: float
    is_anomalous: bool
    feature_vector: Dict[str, float]


class AnomalyDetector:
    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.model: Optional[IsolationForest] = None
        self.scaler = StandardScaler()
        self.feature_names: List[str] = []
        self.is_trained = False
        self.model_path = Path(settings.model_dir) / "isolation_forest.joblib"
        self.scaler_path = Path(settings.model_dir) / "scaler.joblib"
    
    def train(self, sessions: List[SessionAnalysis], crypto_analyzer: CryptoAnalyzer) -> Dict[str, Any]:
        if len(sessions) < 2:
            logger.warning("Not enough sessions to train anomaly detector")
            return {"trained": False, "reason": "insufficient_sessions"}
        
        feature_vectors = []
        valid_sessions = []
        
        for session in sessions:
            fv = crypto_analyzer.get_feature_vector(session)
            feature_vectors.append(list(fv.values()))
            valid_sessions.append(session)
        
        if not feature_vectors:
            return {"trained": False, "reason": "no_features"}
        
        self.feature_names = list(crypto_analyzer.get_feature_vector(sessions[0]).keys())
        
        X = np.array(feature_vectors)
        X_scaled = self.scaler.fit_transform(X)
        
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
        )
        
        self.model.fit(X_scaled)
        self.is_trained = True
        
        self._save_model()
        
        scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)
        
        anomalous_count = sum(1 for p in predictions if p == -1)
        
        return {
            "trained": True,
            "sessions_trained": len(valid_sessions),
            "anomalous_detected": anomalous_count,
            "contamination": self.contamination,
        }
    
    def detect(self, sessions: List[SessionAnalysis], crypto_analyzer: CryptoAnalyzer) -> List[AnomalyResult]:
        if not self.is_trained:
            self._load_model()
        
        if not self.is_trained or self.model is None:
            logger.warning("Anomaly detector not trained, returning empty results")
            return []
        
        results = []
        
        for session in sessions:
            fv = crypto_analyzer.get_feature_vector(session)
            X = np.array([list(fv.values())])
            X_scaled = self.scaler.transform(X)
            
            score = self.model.decision_function(X_scaled)[0]
            prediction = self.model.predict(X_scaled)[0]
            
            normalized_score = (score - self.model.offset_) / -1.0
            normalized_score = max(0.0, min(1.0, (normalized_score + 1) / 2))
            
            is_anomalous = prediction == -1
            
            results.append(AnomalyResult(
                session_id=session.stream_id,
                stream_id=session.stream_id,
                anomaly_score=float(normalized_score),
                is_anomalous=is_anomalous,
                feature_vector=fv,
            ))
        
        return results
    
    def _save_model(self):
        try:
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            logger.info(f"Anomaly model saved to {self.model_path}")
        except Exception as e:
            logger.warning(f"Failed to save anomaly model: {e}")
    
    def _load_model(self):
        try:
            if self.model_path.exists() and self.scaler_path.exists():
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.is_trained = True
                logger.info("Anomaly model loaded from disk")
        except Exception as e:
            logger.warning(f"Failed to load anomaly model: {e}")
    
    def get_model_info(self) -> Dict[str, Any]:
        return {
            "trained": self.is_trained,
            "contamination": self.contamination,
            "n_estimators": self.model.n_estimators if self.model else 0,
            "feature_names": self.feature_names,
        }