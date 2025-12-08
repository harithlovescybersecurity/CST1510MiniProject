class Dataset:
    """represents a data science dataset in the platform"""

    def __init__(self, dataset_id: int, name: str, size_bytes: int, rows: int, source: str):
        self.__id = dataset_id
        self.__name = name
        self.__size_bytes = size_bytes
        self.__rows = rows
        self.__source = source

    def get_id(self) -> int:
        return self.__id

    def get_name(self) -> str:
        return self.__name

    def get_size_bytes(self) -> int:
        return self.__size_bytes

    def get_rows(self) -> int:
        return self.__rows

    def get_source(self) -> str:
        return self.__source

    def calculate_size_mb(self) -> float:
        """converts size from bytes to MB"""
        return self.__size_bytes / (1024 * 1024)

    def is_large(self) -> bool:
        """check if dataset is large"""
        return self.calculate_size_mb() > 100 or self.__rows > 1000000

    def __str__(self) -> str:
        size_mb = self.calculate_size_mb()
        return f"Dataset {self.__id}: {self.__name} ({size_mb:.2f} MB, {self.__rows:,} rows, source: {self.__source})"