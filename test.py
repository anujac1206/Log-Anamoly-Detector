from ai_analyzer import AIAnalyzer

ai = AIAnalyzer(provider="gemini")

print(ai._call_llm("Say hello in one sentence"))