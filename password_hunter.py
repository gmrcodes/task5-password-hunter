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
import tkinter as tk
from tkinter import messagebox

# ==========================================
# Detección de la fuente del S.O.
FUENTE_BASE = "TkDefaultFont"


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
    """Se lanza cuando el jugador acumula 5 cofres malditos y pierde sus vidas."""


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

    MAX_LIVES = 5

    def __init__(self, player_name: str, lives_mode: bool = True) -> None:
        """Inicializa una nueva partida para el jugador en el modo elegido.

        Args:
            player_name: Nombre o nickname del jugador.
            lives_mode: True para jugar con 5 vidas; False para juego libre ilimitado.

        Raises:
            PasswordHunterError: Si el nickname está vacío o es inválido.
        """
        clean_name = self._validate_player_name(player_name)
        super().__init__(clean_name)
        self._lives_mode: bool = lives_mode
        self._score: int = 0
        self._lives: int = self.MAX_LIVES if lives_mode else 0
        self._cursed_count: int = 0
        self._rounds_played: int = 0
        self._history: List[Dict[str, Any]] = []
        self._last_round: Optional[Dict[str, Any]] = None
        mode_label = "Lives Mode (5)" if lives_mode else "Free Mode (Unlimited)"
        GAME_LOGGER.info(
            "Nueva partida iniciada para %s | Modo: %s", self.name, mode_label
        )

    def _validate_player_name(self, player_name: str) -> str:
        """Valida que el nombre o nickname del jugador no esté vacío.

        Args:
            player_name: Texto ingresado por el usuario.

        Returns:
            Nickname limpio de espacios en los extremos.

        Raises:
            PasswordHunterError: Si el nombre tiene menos de 2 caracteres.
        """
        clean_name = str(player_name).strip()
        if len(clean_name) < 2:
            GAME_LOGGER.warning("Nickname inválido ingresado: '%s'", player_name)
            raise PasswordHunterError(
                "Player nickname must have at least 2 characters."
            )
        return clean_name

    @property
    def lives_mode(self) -> bool:
        """Indica si la partida actual tiene límite de 5 vidas (True) o es libre (False)."""
        return self._lives_mode

    @property
    def score(self) -> int:
        """Devuelve el puntaje acumulado actual del jugador."""
        return self._score

    @property
    def lives(self) -> int:
        """Devuelve la cantidad de vidas restantes (0 a 5 en modo vidas)."""
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
        """Indica si el jugador perdió sus 5 vidas (solo aplica en modo vidas)."""
        return self._lives_mode and self._lives <= 0

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
            GameOverError: Si la partida está en modo vidas y se agotan las 5 vidas.
            InvalidLengthError: Si la longitud ingresada no es válida (no resta vidas).
        """
        if self.is_game_over:
            raise GameOverError(
                "Game Over! You have no lives left. Please reset or start a new game."
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

        # 4. Actualizar puntaje, rondas y vidas (solo si el modo vidas está activo)
        self._rounds_played += 1
        self._score += chest.points

        if chest.is_cursed:
            self._cursed_count += 1
            if self._lives_mode:
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
            "lives_mode": self._lives_mode,
            "lives_left": self._lives,
            "cursed_count": self._cursed_count,
        }
        self._last_round = round_result
        self._history.append(round_result)

        # 6. Verificar si se agotaron las 5 vidas tras abrir un cofre maldito
        if self.is_game_over:
            GAME_LOGGER.error(
                "FIN DE LA PARTIDA para %s tras acumular %d cofres malditos. Puntaje final: %d",
                self.name,
                self._cursed_count,
                self._score,
            )
            raise GameOverError(
                f"GAME OVER, {self.name}! You opened {self.MAX_LIVES} Cursed Chests "
                "and lost all your lives."
            )

        return round_result

    def reset_game(self, lives_mode: Optional[bool] = None) -> None:
        """Reinicia puntaje, vidas e historial manteniendo el mismo jugador.

        Args:
            lives_mode: Si se indica, actualiza también el modo de juego (vidas o libre).
        """
        if lives_mode is not None:
            self._lives_mode = lives_mode

        self._score = 0
        self._lives = self.MAX_LIVES if self._lives_mode else 0
        self._cursed_count = 0
        self._rounds_played = 0
        self._history.clear()
        self._last_round = None
        mode_label = "Lives Mode (5)" if self._lives_mode else "Free Mode (Unlimited)"
        GAME_LOGGER.info(
            "Partida reiniciada para %s | Modo: %s", self.name, mode_label
        )

    def get_summary(self) -> str:
        """Devuelve el estado actual del jugador y su partida."""
        lives_info = (
            f"{self._lives}/{self.MAX_LIVES}"
            if self._lives_mode
            else "Unlimited (Free Mode)"
        )
        return (
            f"Player: {self.name} | Score: {self._score} pts | "
            f"Lives: {lives_info} | Rounds: {self._rounds_played}"
        )

# ==========================================
# 7. Interfaz Gráfica (Tkinter) y Arranque
# ==========================================

class HunterGameGUI:
    """Interfaz gráfica en inglés para interactuar con el juego Password Hunter."""

    def __init__(self, root: tk.Tk) -> None:
        """Configura la ventana principal y las variables visuales del juego.

        Args:
            root: Ventana raíz de Tkinter.
        """
        self._root = root
        self._root.title("Password Hunter - Chest Challenge")
        self._root.geometry("710x730")
        self._root.resizable(False, False)
        self._root.configure(bg="#F0F4F8")

        self._game: Optional[HunterGame] = None

        # Variables reactivas vinculadas a los controles de la interfaz
        self._mode_var = tk.StringVar(value="lives")
        self._player_var = tk.StringVar(value="Player: Not registered")
        self._score_var = tk.StringVar(value="Total Score: 0 pts")
        self._lives_var = tk.StringVar(value="Lives: 5 / 5")
        self._password_var = tk.StringVar(value="Generated Password: -")
        self._chest_var = tk.StringVar(value="Chest Obtained: -")
        self._points_var = tk.StringVar(value="Chest Points: 0 pts")
        self._status_var = tk.StringVar(
            value="Enter your nickname, select a game mode, and click 'Start Game'."
        )

        self._build_widgets()

    def _build_widgets(self) -> None:
        """Construye y organiza todos los paneles y controles de la ventana."""
        # Encabezado principal
        header_frame = tk.Frame(self._root, bg="#1B365D", pady=10)
        header_frame.pack(fill=tk.X)

        tk.Label(
            header_frame,
            text="PASSWORD HUNTER: CHEST CHALLENGE",
            font=(FUENTE_BASE, 15, "bold"),
            fg="white",
            bg="#1B365D",
        ).pack()

        # Panel Informativo: Rangos de contraseñas y reglas de cofres
        rules_frame = tk.LabelFrame(
            self._root,
            text=" Chest Rules & Password Length Ranges ",
            font=(FUENTE_BASE, 9, "bold"),
            bg="#EBF8FF",
            fg="#1B365D",
            padx=12,
            pady=6,
        )
        rules_frame.pack(fill=tk.X, padx=16, pady=(10, 4))

        rules_text = (
            "• Length 8-10: Common Chest (+10 pts)   |  "
            "• Length 11-13: Rare Chest (+25 pts)  |\n"
            "• Length 14-16: Legendary Chest (+50 pts)  |  "
            "• Invalid Password: "
            "Cursed Chest (-20 pts | -1 Life in Lives Mode)"
        )
        tk.Label(
            rules_frame,
            text=rules_text,
            font=(FUENTE_BASE, 9),
            fg="#2C5282",
            bg="#EBF8FF",
            justify=tk.LEFT,
            anchor="w",
        ).pack(fill=tk.X)

        # Panel 1: Registro de Nickname y Selección de Modo de Juego
        player_frame = tk.LabelFrame(
            self._root,
            text=" 1. Player Setup & Game Mode ",
            font=(FUENTE_BASE, 10, "bold"),
            bg="#F0F4F8",
            fg="#1B365D",
            padx=12,
            pady=8,
        )
        player_frame.pack(fill=tk.X, padx=16, pady=6)

        top_setup_row = tk.Frame(player_frame, bg="#F0F4F8")
        top_setup_row.pack(fill=tk.X)

        tk.Label(
            top_setup_row, text="Nickname:", font=(FUENTE_BASE, 10), bg="#F0F4F8"
        ).pack(side=tk.LEFT, padx=(0, 6))

        self._name_entry = tk.Entry(top_setup_row, font=(FUENTE_BASE, 10), width=24)
        self._name_entry.pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(
            top_setup_row,
            text="Start Game",
            font=(FUENTE_BASE, 10, "bold"),
            bg="#2B6CB0",
            fg="white",
            command=self._start_new_player,
        ).pack(side=tk.LEFT)

        mode_row = tk.Frame(player_frame, bg="#F0F4F8")
        mode_row.pack(fill=tk.X, pady=(6, 0))

        tk.Label(
            mode_row, text="Game Mode:", font=(FUENTE_BASE, 9, "bold"), bg="#F0F4F8"
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Radiobutton(
            mode_row,
            text="Lives Mode (5 Lives)",
            variable=self._mode_var,
            value="lives",
            font=(FUENTE_BASE, 9),
            bg="#F0F4F8",
            activebackground="#F0F4F8",
            command=self._on_mode_change,
        ).pack(side=tk.LEFT, padx=(0, 14))

        tk.Radiobutton(
            mode_row,
            text="Free Mode (Unlimited)",
            variable=self._mode_var,
            value="free",
            font=(FUENTE_BASE, 9),
            bg="#F0F4F8",
            activebackground="#F0F4F8",
            command=self._on_mode_change,
        ).pack(side=tk.LEFT)

        # Panel 2: Marcador de Jugador, Puntaje Acumulado y Vidas
        stats_frame = tk.Frame(
            self._root, bg="white", bd=1, relief=tk.SOLID, padx=12, pady=10
        )
        stats_frame.pack(fill=tk.X, padx=16, pady=6)

        tk.Label(
            stats_frame,
            textvariable=self._player_var,
            font=(FUENTE_BASE, 10, "bold"),
            fg="#1B365D",
            bg="white",
        ).pack(side=tk.LEFT, expand=True)

        tk.Label(
            stats_frame,
            textvariable=self._score_var,
            font=(FUENTE_BASE, 11, "bold"),
            fg="#1E7E34",
            bg="white",
        ).pack(side=tk.LEFT, expand=True)

        tk.Label(
            stats_frame,
            textvariable=self._lives_var,
            font=(FUENTE_BASE, 11, "bold"),
            fg="#C53030",
            bg="white",
        ).pack(side=tk.LEFT, expand=True)

        # Panel 3: Controles de Ronda (Longitud y Acciones)
        action_frame = tk.LabelFrame(
            self._root,
            text=" 2. Password Generator & Chest Opener ",
            font=(FUENTE_BASE, 10, "bold"),
            bg="#F0F4F8",
            fg="#1B365D",
            padx=12,
            pady=10,
        )
        action_frame.pack(fill=tk.X, padx=16, pady=6)

        tk.Label(
            action_frame,
            text="Length (8-16):",
            font=(FUENTE_BASE, 10),
            bg="#F0F4F8",
        ).pack(side=tk.LEFT, padx=(0, 6))

        self._length_entry = tk.Entry(action_frame, font=(FUENTE_BASE, 10), width=6)
        self._length_entry.insert(0, "10")
        self._length_entry.pack(side=tk.LEFT, padx=(0, 12))

        self._play_button = tk.Button(
            action_frame,
            text="Generate & Open Chest",
            font=(FUENTE_BASE, 10, "bold"),
            bg="#2F855A",
            fg="white",
            state=tk.DISABLED,
            command=self._play_turn,
        )
        self._play_button.pack(side=tk.LEFT, padx=(0, 8))

        self._reset_button = tk.Button(
            action_frame,
            text="Reset Game",
            font=(FUENTE_BASE, 10),
            bg="#D69E2E",
            fg="white",
            state=tk.DISABLED,
            command=self._reset_current_game,
        )
        self._reset_button.pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            action_frame,
            text="Quit",
            font=(FUENTE_BASE, 10),
            bg="#C53030",
            fg="white",
            command=self._exit_game,
        ).pack(side=tk.RIGHT)

        # Panel 4: Resultado del Cofre Actual
        result_frame = tk.LabelFrame(
            self._root,
            text=" 3. Current Chest Result ",
            font=(FUENTE_BASE, 10, "bold"),
            bg="white",
            fg="#1B365D",
            padx=12,
            pady=10,
        )
        result_frame.pack(fill=tk.X, padx=16, pady=6)

        tk.Label(
            result_frame,
            textvariable=self._password_var,
            font=("Consolas", 11, "bold"),
            fg="#2D3748",
            bg="white",
            anchor="w",
        ).pack(fill=tk.X, pady=2)

        self._chest_label = tk.Label(
            result_frame,
            textvariable=self._chest_var,
            font=(FUENTE_BASE, 11, "bold"),
            fg="#1B365D",
            bg="white",
            anchor="w",
        )
        self._chest_label.pack(fill=tk.X, pady=2)

        tk.Label(
            result_frame,
            textvariable=self._points_var,
            font=(FUENTE_BASE, 10, "bold"),
            fg="#2B6CB0",
            bg="white",
            anchor="w",
        ).pack(fill=tk.X, pady=2)

        tk.Label(
            result_frame,
            textvariable=self._status_var,
            font=(FUENTE_BASE, 9, "italic"),
            fg="#4A5568",
            bg="white",
            wraplength=630,
            justify=tk.LEFT,
            anchor="w",
        ).pack(fill=tk.X, pady=(4, 0))

        # Panel 5: Historial Visual de Rondas
        history_frame = tk.LabelFrame(
            self._root,
            text=" 4. Round History ",
            font=(FUENTE_BASE, 10, "bold"),
            bg="#F0F4F8",
            fg="#1B365D",
            padx=12,
            pady=8,
        )
        history_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=(6, 12))

        self._history_text = tk.Text(
            history_frame,
            height=8,
            font=("Consolas", 9),
            bg="#EDF2F7",
            fg="#1A202C",
            state=tk.DISABLED,
        )
        self._history_text.pack(fill=tk.BOTH, expand=True)

    def _is_lives_mode_selected(self) -> bool:
        """Devuelve True si el usuario seleccionó el modo con 5 vidas."""
        return self._mode_var.get() == "lives"

    def _format_lives_display(self) -> str:
        """Construye el texto del marcador de vidas según el modo activo."""
        if self._game is not None:
            if self._game.lives_mode:
                return f"Lives: {self._game.lives} / {HunterGame.MAX_LIVES}"
            return "Mode: Free (Unlimited)"

        return (
            f"Lives: {HunterGame.MAX_LIVES} / {HunterGame.MAX_LIVES}"
            if self._is_lives_mode_selected()
            else "Mode: Free (Unlimited)"
        )

    def _on_mode_change(self) -> None:
        """Sincroniza el marcador visual o reinicia la sesión al cambiar de modo."""
        if self._game is None:
            self._lives_var.set(self._format_lives_display())
            return

        new_lives_mode = self._is_lives_mode_selected()
        if new_lives_mode != self._game.lives_mode:
            self._reset_current_game()
            mode_name = "Lives Mode (5 Lives)" if new_lives_mode else "Free Mode (Unlimited)"
            self._status_var.set(f"Mode switched to {mode_name}. Game reset!")

    def _start_new_player(self) -> None:
        """Crea una nueva partida con el nickname y modo elegidos por el usuario."""
        raw_name = self._name_entry.get()
        use_lives = self._is_lives_mode_selected()
        try:
            self._game = HunterGame(raw_name, lives_mode=use_lives)
        except PasswordHunterError as error:
            messagebox.showwarning("Invalid Nickname", str(error))
            return

        self._player_var.set(f"Player: {self._game.name}")
        self._score_var.set(f"Total Score: {self._game.score} pts")
        self._lives_var.set(self._format_lives_display())
        self._password_var.set("Generated Password: -")
        self._chest_var.set("Chest Obtained: -")
        self._points_var.set("Chest Points: 0 pts")
        self._status_var.set(
            f"Welcome {self._game.name}! Choose a length (8-16) and open a chest."
        )

        self._play_button.config(state=tk.NORMAL)
        self._reset_button.config(state=tk.NORMAL)

        self._history_text.config(state=tk.NORMAL)
        self._history_text.delete("1.0", tk.END)
        self._history_text.config(state=tk.DISABLED)

    def _play_turn(self) -> None:
        """Ejecuta una ronda del juego y actualiza la interfaz con el resultado."""
        if self._game is None:
            messagebox.showinfo("Player Required", "Please enter your nickname first.")
            return

        if self._game.is_game_over:
            messagebox.showerror(
                "Game Over", "You have 0 lives left. Click 'Reset Game' to play again."
            )
            return

        raw_length = self._length_entry.get()
        try:
            round_data = self._game.play_round(raw_length)
            self._update_round_display(round_data)
        except InvalidLengthError as error:
            messagebox.showwarning("Invalid Length", str(error))
        except GameOverError as error:
            # Actualizamos primero el 5to cofre maldito antes de mostrar la alerta
            if self._game.last_round is not None:
                self._update_round_display(self._game.last_round)
            self._play_button.config(state=tk.DISABLED)
            messagebox.showerror("Game Over", str(error))
        except PasswordHunterError as error:
            GAME_LOGGER.error("Error controlado en GUI: %s", error)
            messagebox.showerror("Game Error", str(error))

    def _update_round_display(self, round_data: Dict[str, Any]) -> None:
        """Refresca marcador, tarjeta de cofre e historial con los datos de la ronda.

        Args:
            round_data: Diccionario con los resultados devueltos por play_round.
        """
        points = round_data["points_change"]
        sign = "+" if points > 0 else ""

        self._score_var.set(f"Total Score: {round_data['total_score']} pts")
        self._lives_var.set(self._format_lives_display())
        self._password_var.set(
            f"Generated Password: {round_data['password']} (Length: {round_data['length']})"
        )
        self._chest_var.set(f"Chest Obtained: {round_data['chest_name']}")
        self._points_var.set(f"Chest Points: {sign}{points} pts")
        self._status_var.set(
            f"{round_data['chest_message']} ({round_data['validation_reason']})"
        )

        # Resaltar en rojo si es cofre maldito o en verde si es cofre positivo
        color = "#C53030" if points < 0 else "#1E7E34"
        self._chest_label.config(fg=color)

        lives_log = (
            f"Lives: {round_data['lives_left']}"
            if round_data["lives_mode"]
            else "Free Mode"
        )
        self._history_text.config(state=tk.NORMAL)
        line = (
            f"Round {round_data['round_number']:02d} | "
            f"Pass: {round_data['password']} | "
            f"{round_data['chest_name']} ({sign}{points} pts) | "
            f"Score: {round_data['total_score']} | {lives_log}\n"
        )
        self._history_text.insert(tk.END, line)
        self._history_text.see(tk.END)
        self._history_text.config(state=tk.DISABLED)

    def _reset_current_game(self) -> None:
        """Reinicia el puntaje y las vidas según el modo seleccionado."""
        if self._game is None:
            return

        self._game.reset_game(lives_mode=self._is_lives_mode_selected())
        self._score_var.set("Total Score: 0 pts")
        self._lives_var.set(self._format_lives_display())
        self._password_var.set("Generated Password: -")
        self._chest_var.set("Chest Obtained: -")
        self._points_var.set("Chest Points: 0 pts")
        self._status_var.set("Game reset! Ready for a new run.")
        self._chest_label.config(fg="#1B365D")
        self._play_button.config(state=tk.NORMAL)

        self._history_text.config(state=tk.NORMAL)
        self._history_text.delete("1.0", tk.END)
        self._history_text.config(state=tk.DISABLED)

    def _exit_game(self) -> None:
        """Solicita confirmación y cierra la aplicación registrando la salida en log."""
        if messagebox.askyesno("Quit Game", "Are you sure you want to exit Password Hunter?"):
            GAME_LOGGER.info("Aplicación cerrada por el usuario.")
            self._root.destroy()


def main() -> None:
    """Punto de entrada principal que inicia la interfaz gráfica del juego."""
    root = tk.Tk()
    HunterGameGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()