from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional


class BaseAgent(ABC):
    name: str = "base"


    @abstractmethod
    def run(self, domain: str) -> object:
        """Запускає агент на одному домені й повертає структурований результат."""
        raise NotImplementedError


    # Для майбутніх розширень (контекст, кеш, тощо)
    def set_shared(self, key: str, value: object) -> None:
        setattr(self, key, value)


    def get_shared(self, key: str, default: Optional[object] = None) -> object:
        return getattr(self, key, default)