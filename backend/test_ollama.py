
from app.services.ai_service import generate_response

if __name__ == "__main__":
    try:
        answer = generate_response(
            "Say hello. You are the AI engine of ProofBox AI."
        )

        print("\nOllama Cloud connection successful!")
        print("Model response:")
        print(answer)

    except Exception as error:
        print("Ollama connection failed:")
        print(error)
