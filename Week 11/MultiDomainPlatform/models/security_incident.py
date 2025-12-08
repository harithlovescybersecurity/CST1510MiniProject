class SecurityIncident:
    """Represents a cybersecurity incident in the platform"""

    def __init__(self, incident_id: int, incident_type: str, severity: str, status: str, description:str):
        self.__id = incident_id
        self.__incident_type = incident_type
        self.__severity = severity
        self.__status = status
        self.__description = description

    def get_id(self) -> int:
        return self.__id

    def get_incident_type(self) -> str:
        return self.__incident_type

    def get_severity(self) -> str:
        return self.__severity

    def get_status(self) -> str:
        return self.__status

    def get_description(self) -> str:
        return self.__description

    def update_status(self, new_status: str) -> None:
        """update the status of this incident"""
        self.__status = new_status

    def get_severity_level(self) -> int:
        """return an integer severity level"""
        mapping = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        return mapping.get(self.__severity.lower(), 0)

    def is_critical(self) -> bool:
        """check if incident is critical"""
        return self.get_severity_level() >= 3

    def __str__(self) -> str:
        return f"Incident #{self.__id} [{self.__severity.upper()}] {self.__incident_type}: {self.__description[:50]}..."