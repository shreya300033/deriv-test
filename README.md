# deriv-test

## Configuration

Create a `.env` file in the project root (same folder as `pipeline.py`) with your Groq API key:

```env
GROQ_API_KEY=your_key_here
```

`pipeline.py` loads this via [python-dotenv](https://pypi.org/project/python-dotenv/) when it starts. Do not commit `.env`; keep it local only.