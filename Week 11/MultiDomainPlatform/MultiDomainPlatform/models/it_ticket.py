class ITTicket:
    """Represents an IT operations ticket in the platform."""

    def __init__(self, ticket_id: str, priority: str, status: str, category: str, subject: str, description: str, created_date: str, assigned_to: str,db_id: int = None):
        self.__id = db_id  # Database primary key
        self.__ticket_id = ticket_id  # External ID like "TICKET-001"
        self.__priority = priority
        self.__status = status
        self.__category = category
        self.__subject = subject
        self.__description = description
        self.__created_date = created_date
        self.__assigned_to = assigned_to

    # Getter methods
    def get_id(self) -> int:
        return self.__id

    def get_ticket_id(self) -> str:
        return self.__ticket_id

    def get_priority(self) -> str:
        return self.__priority

    def get_status(self) -> str:
        return self.__status
    
    def get_category(self) -> str:
        return self.__category

    def get_subject(self) -> str:
        return self.__subject

    def get_description(self) -> str:
        return self.__description

    def get_created_date(self) -> str:
        return self.__created_date

    def get_assigned_to(self) -> str:
        return self.__assigned_to

    # Business logic methods
    def is_high_priority(self) -> bool:
        """Check if ticket is high priority."""
        return self.__priority.lower() in ["high", "critical", "urgent"]

    def is_open(self) -> bool:
        """Check if ticket is still open."""
        return self.__status.lower() in ["open", "in progress", "pending"]

    def get_priority_level(self) -> int:
        """Return numeric priority level for sorting."""
        priority_map = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
            "urgent": 5
        }
        return priority_map.get(self.__priority.lower(), 0)

    def assign_to(self, new_assignee: str):
        """Assign ticket to someone."""
        self.__assigned_to = new_assignee

    def update_status(self, new_status: str):
        """Update ticket status."""
        self.__status = new_status

    def __str__(self) -> str:
        return f"ITTicket {self.__ticket_id}: {self.__subject} ({self.__priority} priority, {self.__status})"