"""Juego Interactivo: Cazador de Contraseñas (Password Hunter).

Sistema orientado a objetos desarrollado en Python 3 que implementa
abstracción, herencia, polimorfismo, encapsulación y manejo de excepciones
personalizadas con registro de eventos en archivo log.
"""

from abc import ABC, abstractmethod
import logging


# ==========================================
# 1. Configuración del Sistema de Logs
# ==========================================

def setup_logger(log_filename: str = "password_hunter.log") -> logging.Logger:
    """Configura y devuelve el registrador de eventos y errores del juego.

    Returns:
        Instancia configurada de logging.Logger.
    """
    logger = logging.getLogger("PasswordHunter")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        file_handler = logging.FileHandler(log_filename, mode="a", encoding="utf-8")
        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


GAME_LOGGER = setup_logger()


# ==========================================
# 2. Excepciones Personalizadas del Juego
# ==========================================

class PasswordHunterError(Exception):
    """Excepción base para todos los errores controlados del juego."""


class InvalidLengthError(PasswordHunterError):
    """Se lanza cuando la longitud ingresada no es numérica o está fuera de rango (8-16)."""


class InvalidPasswordError(PasswordHunterError):
    """Se lanza cuando la contraseña generada incumple alguna regla de seguridad."""


class GameOverError(PasswordHunterError):
    """Se lanza cuando el jugador acumula 3 cofres malditos y pierde sus vidas."""


# ==========================================
# 3. Clase Abstracta Base (Abstracción)
# ==========================================

class GameEntity(ABC):
    """Clase abstracta base que define el contrato común para entidades del juego."""

    def __init__(self, name: str) -> None:
        """Inicializa la entidad con un nombre encapsulado.

        Args:
            name: Nombre descriptivo de la entidad.
        """
        self._name = name

    @property
    def name(self) -> str:
        """Devuelve el nombre encapsulado de la entidad."""
        return self._name

    @abstractmethod
    def get_summary(self) -> str:
        """Método abstracto que cada subclase debe implementar para describirse."""
        pass