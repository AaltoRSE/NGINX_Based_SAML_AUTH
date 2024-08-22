from pytest_mock_resources import create_mongo_fixture
from session import SessionHandler
from fastapi import HTTPException


mongo = create_mongo_fixture()


# Testing whether keys are checked correctly
def test_create_session(mongo):
    handler = SessionHandler(True)
    handler.setup(mongo)
    session_key = handler.create_session({"Some": "Data"})
    session_key2 = handler.create_session(
        {"Some": "OtherData"}, session_key=session_key
    )
    assert session_key != session_key2
    assert handler.get_session_data(session_key)["Some"] == "Data"
    assert handler.get_session_data(session_key2)["Some"] == "OtherData"


def test_expire_session(mongo):
    handler = SessionHandler(True, 0)
    handler.setup(mongo)
    session_key = handler.create_session({"Some": "Data"})
    failed = False
    try:
        handler.get_session_data(session_key)["Some"] == "Data"
    except HTTPException as e:
        assert e.detail == "Session expired"
        failed = True
    assert failed
