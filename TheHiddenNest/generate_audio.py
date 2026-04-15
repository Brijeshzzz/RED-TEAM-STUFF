import numpy as np
import wave

MORSE_CODE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....',
    '7': '--...', '8': '---..', '9': '----.', ' ': '/'
}

MESSAGE = "KEY PHOENIX STOP ENCODED TFBHR3tTV1xMRzFRT2tsUVQwRlVTVE09"

SAMPLE_RATE = 44100
DOT_DURATION = 0.1
FREQUENCY = 800

def tone(duration):
    t = np.linspace(0, duration, int(SAMPLE_RATE * duration), False)
    return np.sin(2 * np.pi * FREQUENCY * t)

audio = np.array([])

for char in MESSAGE.upper():
    code = MORSE_CODE.get(char, '')
    for symbol in code:
        if symbol == '.':
            audio = np.concatenate((audio, tone(DOT_DURATION)))
        elif symbol == '-':
            audio = np.concatenate((audio, tone(DOT_DURATION * 3)))
        audio = np.concatenate((audio, np.zeros(int(SAMPLE_RATE * DOT_DURATION))))
    audio = np.concatenate((audio, np.zeros(int(SAMPLE_RATE * DOT_DURATION * 3))))

audio = (audio * 32767).astype(np.int16)

with wave.open("build/audio.wav", "w") as f:
    f.setnchannels(1)
    f.setsampwidth(2)
    f.setframerate(SAMPLE_RATE)
    f.writeframes(audio.tobytes())
