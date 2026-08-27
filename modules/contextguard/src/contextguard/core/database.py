#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr  6 07:40:48 2026

@author: hounsousamuel
"""

import sys, os
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))
from sqlmodel import (
    SQLModel, create_engine, 
    select, Field, Column, 
    JSON, Session
    )
from typing import Optional, Dict
from datetime import datetime
from dotenv import load_dotenv

class User(SQLModel, table=True):
    __table_args__ = {"extend_existing": True}
    id:Optional[int] = Field(default=None, primary_key=True, description="User ID")
    username:str = Field(default_factory=str)
    password:bytes = Field(default_factory=bytes)
    history:Dict[str, str] = Field(default_factory=dict, sa_column=Column(JSON), description="Historique de l'utilisateur")
    created_at:datetime = Field(default_factory=datetime.utcnow)

class DBManager:
    load_dotenv()
    SQLURI = os.getenv("CONTEXTGUARDURL")
    if SQLURI is None:
        raise ValueError("Url sqlite non trouvée !")
        
    def __init__(self):
        self.engine = create_engine(self.SQLURI)
        SQLModel.metadata.create_all(self.engine)
    
    def add_user(self, *args, **kwargs) -> dict[str, str|bool]:
        result = {
            "error": "",
            "success": False,
            "id": ""
            }
        # print(kwargs)
        # user = User(**kwargs)
        # input(user)
        with Session(self.engine) as session:
            try:
                user = User(**kwargs)
                session.add(user)
                session.commit()
                session.refresh(user)
                result["id"] = user.id
                result["success"] = True
                return result
            except Exception as e:
                print("Erreur survenue dans l'ajout de l'user :", str(e))
                result["error"] = str(e)
                session.rollback()
                return result
    
    def get_user_by_id(self, id:str) -> dict:
        result = {
            "user": None,
            "success": False,
            "error": ""
            }
        with Session(self.engine) as session:
            try:
                user = session.get(User, id)
                if user:
                    result["user"] = user
                result["success"] = True
                return result
            except Exception as e:
                print("Erreur survenue dans la recherche de l'user avec id", id, "erreur :", str(e))
                result["error"] = str(e)
                return result
    
    def get_user_by_name(self, name:str) -> dict:
        result = {
            "user": [],
            "success": False,
            "error": ""
            }
        with Session(self.engine) as session:
            try:
                query = select(User).where(User.username == name)
                users = list(session.exec(query).all())
                if users:
                    result["user"] = users
                result["success"] = True
                return result
            except Exception as e:
                print("Erreur survenue dans la recherche de l'user par nom:", str(e))
                result["error"] = str(e)
                return result
    
    def delete_user_by_id(self, id:str) -> dict:
        result = {
            "success": False,
            "error": ""
            }
        with Session(self.engine) as session:
            try:
                user = session.get(User, id)
                if user:
                    session.delete(user)
                    session.commit()
                result["success"] = True
                return result
            except Exception as e:
                print("Erreur survenue dans la suppression de l'user avec id", id, "erreur :", str(e))
                result["error"] = str(e)
                session.rollback()
                return result
    
    def delete_user_by_name(self, name:str, all:bool = False) -> dict:
        result = {
            "success": False,
            "error": ""
            }
        with Session(self.engine) as session:
            try:
                query = select(User).where(User.username == name)
                users = list(session.exec(query).all())
                if users:
                    if all:
                        for user in users:
                            session.delete(user)
                    else:
                        session.delete(users[0])
                    session.commit()
                result["success"] = True
                return result
            except Exception as e:
                print("Erreur survenue dans la suppression de l'user avec par nom:", str(e))
                session.rollback()
                result["error"] = str(e)
                return result
    
    def update_history_by_name(self, name:str, history:dict = {}):
        result = {
            "success": False,
            "error": ""
            }
        with Session(self.engine) as session:
            try:
                query = select(User).where(User.username == name)
                user = list(session.exec(query).all())
                if user:
                    user = user[0]
                    if user.history:
                        new_history = dict(user.history)
                        new_history.update(history)
                        user.history = new_history
                    else:
                        user.history = history
                session.commit()
                result["success"] = True
                return result
            except Exception as e:
                print("Erreur survenue dans la mise à jour d'historique par id:", str(e))
                result["error"] = str(e)
                session.rollback()
                return result
        
    def update_history_by_id(self, id:str, history:dict = {}):
        result = {
            "success": False,
            "error": ""
            }
        with Session(self.engine) as session:
            try:
                user:User = session.get(User, id)
                if user:
                    if user.history:
                        new_history = dict(user.history)
                        new_history.update(history)
                        user.history = new_history
                    else:
                        user.history = history
                session.commit()
                result["success"] = True
                return result
            except Exception as e:
                print("Erreur survenue dans la mise à jour d'historique par nom:", str(e))
                result["error"] = str(e)
                session.rollback()
                return result


    
if __name__ == "__main__":
    dbm = DBManager()

    print(dbm.add_user(username="Samuel", password="16".encode(), history={}) )
    print(dbm.add_user(username="sam", password="15".encode()))
    print(dbm.add_user(username="sam", password="10".encode()))
    # try:
    #     print(dbm.add_user(None, 19))
    # except Exception as e:
    #     print(e)

    # try:
    #     print(dbm.add_user("ben", -1))
    # except Exception as e:
    #     print(e)

    print(dbm.get_user_by_name("sam"))
    # dbm.engine.clear_compiled_cache()
    print(dbm.get_user_by_name("sam"))
    
