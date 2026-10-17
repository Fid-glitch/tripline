import unittest
from unittest.mock import Mock, patch

from agent.chatbot import _groq_chat


class TestChatbot(unittest.TestCase):
    @patch("agent.chatbot.requests.post")
    @patch.dict("os.environ", {"GROQ_API_KEY": "test-api-key"})
    def test_groq_request_uses_configured_api_key(self, post):
        response = Mock()
        response.json.return_value = {
            "choices": [{"message": {"content": "Hello"}}]
        }
        post.return_value = response

        result = _groq_chat([{"role": "user", "content": "Hi"}])

        self.assertEqual(result, "Hello")
        self.assertEqual(
            post.call_args.kwargs["headers"]["Authorization"],
            "Bearer test-api-key",
        )


if __name__ == "__main__":
    unittest.main()
