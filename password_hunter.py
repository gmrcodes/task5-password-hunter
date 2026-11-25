"""Juego Interactivo: Cazador de Contraseñas (Password Hunter).

Sistema orientado a objetos desarrollado en Python 3 que implementa
abstracción, herencia, polimorfismo, encapsulación y manejo de excepciones
personalizadas con registro de eventos en archivo log.
"""


from abc import ABC, abstractmethod
import logging
import random
import string
from typing import Any, Dict, List, Optional


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

    # ==========================================
# 6. Clase HunterGame (Lógica y Estado del Juego)
# ==========================================

class HunterGame(GameEntity):
    """Administra el jugador, el puntaje acumulado, las vidas y el flujo de rondas."""

    MAX_LIVES = 3

    def __init__(self, player_name: str) -> None:
        """Inicializa una nueva partida para el jugador indicado.

        Args:
            player_name: Nombre o nickname del jugador.

        Raises:
            PasswordHunterError: Si el nickname está vacío o es inválido.
        """
        clean_name = self._validate_player_name(player_name)
        super().__init__(clean_name)
        self._score: int = 0
        self._lives: int = self.MAX_LIVES
        self._cursed_count: int = 0
        self._rounds_played: int = 0
        self._history: List[Dict[str, Any]] = []
        self._last_round: Optional[Dict[str, Any]] = None
        GAME_LOGGER.info("Nueva partida iniciada para el jugador: %s", self.name)

    def _validate_player_name(self, player_name: str) -> str:
        """Valida que el nombre o nickname del jugador no esté vacío.

        Returns:
            Nickname limpio de espacios en los extremos.

        Raises:
            PasswordHunterError: Si el nombre tiene menos de 3 caracteres.
        """
        clean_name = str(player_name).strip()
        if len(clean_name) < 3:
            GAME_LOGGER.warning("Nickname inválido ingresado: '%s'", player_name)
            raise PasswordHunterError(
                "Player nickname must have at least 3 characters."
            )
        return clean_name

    @property
    def score(self) -> int:
        """Devuelve el puntaje acumulado actual del jugador."""
        return self._score

    @property
    def lives(self) -> int:
        """Devuelve la cantidad de vidas restantes (0 a 3)."""
        return self._lives

    @property
    def cursed_count(self) -> int:
        """Devuelve cuántos cofres malditos ha abierto el jugador."""
        return self._cursed_count

    @property
    def rounds_played(self) -> int:
        """Devuelve el total de rondas jugadas en la partida."""
        return self._rounds_played

    @property
    def is_game_over(self) -> bool:
        """Indica si el jugador perdió todas sus vidas (3 cofres malditos)."""
        return self._lives <= 0

    @property
    def last_round(self) -> Optional[Dict[str, Any]]:
        """Devuelve los datos detallados de la última ronda ejecutada."""
        return self._last_round

    @property
    def history(self) -> List[Dict[str, Any]]:
        """Devuelve una copia del historial de rondas jugadas."""
        return list(self._history)

    def play_round(self, raw_length: str) -> Dict[str, Any]:
        """Ejecuta una ronda completa: genera contraseña, valida y abre un cofre.

        Args:
            raw_length: Longitud solicitada por el jugador como texto.

        Returns:
            Diccionario con los resultados de la ronda para mostrar en pantalla.

        Raises:
            GameOverError: Si la partida ya terminó o termina en esta ronda.
            InvalidLengthError: Si la longitud ingresada no es válida (no resta vidas).
        """
        if self.is_game_over:
            raise GameOverError(
                "Game Over! You have no lives left. Please start a new game."
            )

        # 1. Crear y generar la contraseña (puede lanzar InvalidLengthError)
        password = Password(raw_length)

        # 2. Validar las reglas de seguridad de la contraseña
        is_valid = True
        validation_reason = "All security requirements met."
        try:
            password.validate()
        except InvalidPasswordError as error:
            is_valid = False
            validation_reason = str(error)
            GAME_LOGGER.warning(
                "Ronda %d - Contraseña inválida '%s': %s",
                self._rounds_played + 1,
                password.value,
                validation_reason,
            )

        # 3. Seleccionar y abrir el cofre correspondiente usando polimorfismo
        chest = create_chest_for_password(password, is_valid)
        chest_message = chest.open_chest()

        # 4. Actualizar puntaje, rondas y vidas según el tipo de cofre
        self._rounds_played += 1
        self._score += chest.points

        if chest.is_cursed:
            self._cursed_count += 1
            self._lives -= 1

        # 5. Guardar el resumen de la ronda en el historial interno
        round_result: Dict[str, Any] = {
            "round_number": self._rounds_played,
            "password": password.value,
            "length": password.length,
            "is_valid": is_valid,
            "validation_reason": validation_reason,
            "chest_name": chest.name,
            "points_change": chest.points,
            "chest_message": chest_message,
            "total_score": self._score,
            "lives_left": self._lives,
            "cursed_count": self._cursed_count,
        }
        self._last_round = round_result
        self._history.append(round_result)

        # 6. Verificar si se agotaron las 3 vidas tras abrir un cofre maldito
        if self.is_game_over:
            GAME_LOGGER.error(
                "FIN DE LA PARTIDA para %s tras acumular %d cofres malditos. Puntaje final: %d",
                self.name,
                self._cursed_count,
                self._score,
            )
            raise GameOverError(
                f"GAME OVER, {self.name}! You opened 3 Cursed Chests and lost all your lives."
            )

        return round_result

    def reset_game(self) -> None:
        """Reinicia puntaje, vidas e historial manteniendo el mismo jugador."""
        self._score = 0
        self._lives = self.MAX_LIVES
        self._cursed_count = 0
        self._rounds_played = 0
        self._history.clear()
        self._last_round = None
        GAME_LOGGER.info("Partida reiniciada para el jugador: %s", self.name)

    def get_summary(self) -> str:
        """Devuelve el estado actual del jugador y su partida."""
        return (
            f"Player: {self.name} | Score: {self._score} pts | "
            f"Lives: {self._lives}/{self.MAX_LIVES} | Rounds: {self._rounds_played}"
        )