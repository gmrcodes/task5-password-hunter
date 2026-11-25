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

    # ==========================================
# 5. Clases de Cofres (Herencia y Polimorfismo)
# ==========================================

class Chest(GameEntity, ABC):
    """Clase abstracta base que representa un cofre del juego."""

    def __init__(self, name: str, points: int, is_cursed: bool = False) -> None:
        """Inicializa un cofre con su nombre, puntaje y estado de maldición.

        Args:
            name: Nombre visible del tipo de cofre.
            points: Puntos que suma (positivo) o resta (negativo) al abrirse.
            is_cursed: Indica si el cofre es maldito (True) o beneficioso (False).
        """
        super().__init__(name)
        self._points = points
        self._is_cursed = is_cursed

    @property
    def points(self) -> int:
        """Devuelve el valor en puntos del cofre."""
        return self._points

    @property
    def is_cursed(self) -> bool:
        """Indica si el cofre resta una vida al jugador."""
        return self._is_cursed

    @abstractmethod
    def open_chest(self) -> str:
        """Abre el cofre y devuelve un mensaje con el resultado obtenido."""
        pass

    def get_summary(self) -> str:
        """Devuelve un resumen general del cofre y su valor en puntos."""
        sign = "+" if self._points > 0 else ""
        return f"{self.name} ({sign}{self._points} pts)"


class CommonChest(Chest):
    """Cofre común otorgado por contraseñas válidas de longitud 8 a 10."""

    def __init__(self) -> None:
        """Configura el cofre común con +10 puntos."""
        super().__init__(name="Common Chest", points=10, is_cursed=False)

    def open_chest(self) -> str:
        """Abre el cofre común aplicando polimorfismo."""
        GAME_LOGGER.info("Cofre abierto: %s (+%d puntos).", self.name, self.points)
        return f"You opened a {self.name}! You earned +{self.points} points."


class RareChest(Chest):
    """Cofre raro otorgado por contraseñas válidas de longitud 11 a 13."""

    def __init__(self) -> None:
        """Configura el cofre raro con +25 puntos."""
        super().__init__(name="Rare Chest", points=25, is_cursed=False)

    def open_chest(self) -> str:
        """Abre el cofre raro aplicando polimorfismo."""
        GAME_LOGGER.info("Cofre abierto: %s (+%d puntos).", self.name, self.points)
        return f"Great job! You unlocked a {self.name} and earned +{self.points} points."


class LegendaryChest(Chest):
    """Cofre legendario otorgado por contraseñas válidas de longitud 14 a 16."""

    def __init__(self) -> None:
        """Configura el cofre legendario con +50 puntos."""
        super().__init__(name="Legendary Chest", points=50, is_cursed=False)

    def open_chest(self) -> str:
        """Abre el cofre legendario aplicando polimorfismo."""
        GAME_LOGGER.info("Cofre abierto: %s (+%d puntos).", self.name, self.points)
        return f"JACKPOT! You unlocked a {self.name} and earned +{self.points} points!"


class CursedChest(Chest):
    """Cofre maldito otorgado cuando la contraseña generada es inválida."""

    def __init__(self) -> None:
        """Configura el cofre maldito con -20 puntos y marca de maldición."""
        super().__init__(name="Cursed Chest", points=-20, is_cursed=True)

    def open_chest(self) -> str:
        """Abre el cofre maldito aplicando polimorfismo."""
        GAME_LOGGER.warning("Cofre maldito activado: %s (%d puntos).", self.name, self.points)
        return f"OH NO! It is a {self.name}! You lost {abs(self.points)} points and 1 life."


def create_chest_for_password(password: Password, is_valid: bool) -> Chest:
    """Selecciona y crea el cofre adecuado según la validez y longitud de la contraseña.

    Args:
        password: Instancia de Password evaluada en la ronda actual.
        is_valid: True si la contraseña pasó todas las validaciones; False si falló.

    Returns:
        Una instancia concreta de una subclase de Chest.
    """
    if not is_valid:
        return CursedChest()

    if 8 <= password.length <= 10:
        return CommonChest()
    elif 11 <= password.length <= 13:
        return RareChest()
    else:
        return LegendaryChest()