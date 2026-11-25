"""Juego Interactivo: Cazador de Contraseñas (Password Hunter).

Sistema orientado a objetos desarrollado en Python 3 que implementa
abstracción, herencia, polimorfismo, encapsulación y manejo de excepciones
personalizadas con registro de eventos en archivo log.
"""


from abc import ABC, abstractmethod
import logging
import random
import string


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

# ==========================================
# 4. Clase Password (Encapsulación y Validación)
# ==========================================

class Password(GameEntity):
    """Encapsula la generación aleatoria y validación de contraseñas."""

    # Lista exacta de caracteres especiales permitidos en el enunciado
    SPECIAL_CHARS = "¿¡?=)(/*+-%&$#!"
    MIN_LENGTH = 8
    MAX_LENGTH = 16

    def __init__(self, raw_length: str) -> None:
        """Inicializa y genera una contraseña aleatoria a partir de la longitud pedida.

        Raises:
            InvalidLengthError: Si la longitud no es numérica o está fuera de 8-16.
        """
        super().__init__("Generated Password")
        self._length = self._validate_length(raw_length)
        self._value = self._generate_random_password()

    def _validate_length(self, raw_length: str) -> int:
        """Convierte y valida que la longitud sea un entero entre 8 y 16.

        Returns:
            Longitud validada como número entero.

        Raises:
            InvalidLengthError: Si el valor no es entero o está fuera de rango.
        """
        try:
            length = int(str(raw_length).strip())
        except ValueError as error:
            GAME_LOGGER.warning("Longitud no numérica ingresada: '%s'", raw_length)
            raise InvalidLengthError(
                f"Invalid length '{raw_length}': must be a whole number."
            ) from error

        if length < self.MIN_LENGTH or length > self.MAX_LENGTH:
            GAME_LOGGER.warning("Longitud fuera de rango ingresada: %d", length)
            raise InvalidLengthError(
                f"Length {length} out of range: must be between "
                f"{self.MIN_LENGTH} and {self.MAX_LENGTH}."
            )
        return length

    def _generate_random_password(self) -> str:
        """Genera una cadena totalmente aleatoria sin orden predecible.

        Al elegir libremente de todo el conjunto permitido (con posibilidad de
        repetición o ausencia de alguna categoría), algunas contraseñas serán
        válidas y otras fallarán, activando los cofres malditos.

        Returns:
            Cadena de texto aleatoria de longitud self._length.
        """
        allowed_pool = (
            string.ascii_uppercase
            + string.ascii_lowercase
            + string.digits
            + self.SPECIAL_CHARS
        )
        characters = []
        for _ in range(self._length):
            characters.append(random.choice(allowed_pool))

        # Mezclamos adicionalmente para garantizar aleatoriedad sin orden predecible
        random.shuffle(characters)
        return "".join(characters)

    @property
    def length(self) -> int:
        """Devuelve la longitud validada de la contraseña."""
        return self._length

    @property
    def value(self) -> str:
        """Devuelve el texto de la contraseña generada."""
        return self._value

    def validate(self) -> bool:
        """Verifica estrictamente las 6 reglas de seguridad de la contraseña.

        Returns:
            True si cumple todas las reglas de seguridad.

        Raises:
            InvalidPasswordError: Detallando exactamente qué regla falló.
        """
        if len(self._value) < self.MIN_LENGTH:
            raise InvalidPasswordError("Password must have at least 8 characters.")

        has_upper = any(char.isupper() for char in self._value)
        if not has_upper:
            raise InvalidPasswordError("Missing at least one uppercase letter (A-Z).")

        has_lower = any(char.islower() for char in self._value)
        if not has_lower:
            raise InvalidPasswordError("Missing at least one lowercase letter (a-z).")

        has_digit = any(char.isdigit() for char in self._value)
        if not has_digit:
            raise InvalidPasswordError("Missing at least one number (0-9).")

        has_special = any(char in self.SPECIAL_CHARS for char in self._value)
        if not has_special:
            raise InvalidPasswordError(
                f"Missing a valid special character ({self.SPECIAL_CHARS})."
            )

        # Un conjunto (set) elimina duplicados; si el tamaño difiere, hubo repetición
        if len(set(self._value)) != len(self._value):
            raise InvalidPasswordError("Password contains repeated characters.")

        return True

    def get_summary(self) -> str:
        """Devuelve una descripción legible de la contraseña generada."""
        return f"{self.name}: '{self._value}' (Length: {self._length})"