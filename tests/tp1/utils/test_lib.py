from src.tp1.utils.lib import choose_interface, hello_world


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


def test_when_choose_interface_then_return_empty_string():
    # When
    result = choose_interface()

    # Then
    assert result == ""
