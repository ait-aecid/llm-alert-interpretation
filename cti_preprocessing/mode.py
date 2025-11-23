from enum import Enum

class CTIProcessingMode(Enum):
    FULL_TEXT = 1
    FULL_TEXT_WITH_ENTITY_IOC_EXTR = 2
    ATTACKG_GRAPH = 3
    ATTACKG_MITRE = 4
    
