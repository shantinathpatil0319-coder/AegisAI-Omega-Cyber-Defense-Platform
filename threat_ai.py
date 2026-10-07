import numpy as np
from tensorflow.keras.models import load_model

model = load_model("../model/cyber_model.h5")

labels = ["Normal","DoS","Probe","Ransomware"]

def detect_attack(features):
    p = model.predict(np.array([features]))
    idx = np.argmax(p)
    severity = [1,7,5,10]
    return labels[idx], severity[idx]