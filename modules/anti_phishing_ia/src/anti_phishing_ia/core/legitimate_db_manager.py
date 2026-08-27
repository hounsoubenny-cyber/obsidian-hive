#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 13 04:07:06 2026

@author: hounsousamuel
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import Levenshtein
import pickle
from pybktree import BKTree
from sqlmodel import SQLModel, Field, Session, select, func, create_engine, or_
from datetime import datetime
from typing import Optional, List
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from anti_phishing_ia.core.config import DB_PATH, LEGIT_BATCH_SIZE
from anti_phishing_ia.phishing_utils.utils import _get_domain

BKTREE_PATH = os.path.join(os.path.dirname(DB_PATH), "domains_bktree.pkl")

class LegitDomain(SQLModel, table=True):
    __table_args__ = {"extend_existing": True}
    __tablename__ = "legit_domain"
    id: Optional[int] = Field(default=None, primary_key=True)
    domain: str = Field(default_factory=str, index=True, unique=True)
    length: int = Field(default=0, index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class LegitDomainDBManager:
    MAX_ROWS_PER_INSERT = 500
    def __init__(self):
        self.db_path = f"sqlite:///{DB_PATH}"
        self.engine = create_engine(self.db_path, echo=False, connect_args={"check_same_thread": False})
        try:
            SQLModel.metadata.create_all(self.engine)
        except Exception as e:
            if "already exists" not in str(e):
                raise
                
        self._bktree: BKTree | None = None
        # self._load_or_build_bktree()
    
    def _load_or_build_bktree(self):
        """Charge le BK-Tree depuis disque ou le reconstruit."""
        if os.path.exists(BKTREE_PATH):
            print("📂 Chargement BK-Tree...")
            with open(BKTREE_PATH, "rb") as f:
                self._bktree = pickle.load(f)
            print("✅ BK-Tree chargé")
        else:
            print("🔨 Construction BK-Tree...")
            all_domains = self.get_all_legit_domain()
            self._bktree = BKTree(Levenshtein.distance, all_domains)
            with open(BKTREE_PATH, "wb") as f:
                pickle.dump(self._bktree, f)
            print("✅ BK-Tree construit et sauvegardé")
    
    def get_session(self) -> Session:
        return Session(self.engine)
    
    def create_legit_domain(self, domain: str) -> None | LegitDomain:
        domain = domain.strip().lower()
        with self.get_session() as session:
            try:
                if not self.includes(domain):
                    legit_domain = LegitDomain(domain=domain, length=len(domain))
                    session.add(legit_domain)
                    session.commit()
                    session.refresh(legit_domain)
                    return legit_domain
            except Exception as e:
                session.rollback()
                print(f"❌ ERREUR create_legit_domain: {e}")
                return None
    
    def create_legit_domain_by_lot(self, domains: List[str]):
        domains = list({d.strip().lower() for d in domains if d.strip()})
        inserted_total = 0
        with self.get_session() as session:
            before = session.exec(select(func.count(LegitDomain.id))).one()
    
            for i in range(0, len(domains), self.MAX_ROWS_PER_INSERT):
                sub_batch = domains[i:i + self.MAX_ROWS_PER_INSERT]
                stmt = sqlite_insert(LegitDomain).values(
                    [{"domain": d, "length": len(d)} for d in sub_batch]
                ).on_conflict_do_nothing(index_elements=["domain"])
                session.exec(stmt)
    
            session.commit()
            after = session.exec(select(func.count(LegitDomain.id))).one()
            inserted_total = after - before
    
        return inserted_total, len(domains)
        
    def get_legit_domain_count_for(self, domain: str, id: int = None):
        with self.get_session() as session:
            return session.exec(
                select(func.count(LegitDomain.id))
                .where(
                    or_(
                        LegitDomain.id == id,
                        LegitDomain.domain == domain
                    )
                )
            ).one()
    
    def get_legit_domain_count(self):
        with self.get_session() as session:
            return session.exec(
                select(func.count(LegitDomain.id))
            ).one()
    
    def get_all_legit_domain(self) -> List[LegitDomain]:
        with self.get_session() as session:
            return session.exec(
                select(LegitDomain.domain)
            ).all()
        
    def get_legit_domain(self, domain: str, id: int = None) -> str | None:
        with self.get_session() as session:
            return session.exec(
                select(LegitDomain.domain)
                .where(
                    or_(
                        LegitDomain.id == id,
                        LegitDomain.domain == domain
                    )
                )
            ).first()
    
    def includes(self, domain: str, id: int = None) -> bool:
        return self.get_legit_domain(domain, id) is not None
    
    def get_range(self, start: int, end: int) -> List[str]:
        if start < 0:
            raise ValueError(f"start ne peut pas être négatif: {start}")
        if end < start:
            raise ValueError(f"end ({end}) doit être >= start ({start})")
        
        count = self.get_legit_domain_count()
        if start >= count:
            return []
        if end > count:
            end = count
        
        with self.get_session() as session:
            statement = select(LegitDomain.domain).offset(start).limit(end - start)
            results = session.exec(statement).all()
            return list(results)
    
    def get_page(self, page: int, page_size: int = 100) -> List[str]:
        start = page * page_size
        end = start + page_size
        return self.get_range(start, end)
    
    def _get_similar_length_domains(self, domain: str, ratio: float = 0.3) -> List[str]:
        length = len(domain)
        min_len = max(1, int(length * (1 - ratio)))
        max_len = int(length * (1 + ratio))
        first_char = domain[0].lower()
        with self.get_session() as session:
            statement = select(LegitDomain.domain).where(
                LegitDomain.length.between(min_len, max_len),
                LegitDomain.domain.startswith(first_char)
            )
            results = session.exec(statement).all()
            return list(results)
    
    def _bktree_find_similar(self, domain: str, max_distance: int = 4, return_distance: bool = False) -> list:
        domain = domain.strip().lower()
        results = self._bktree.find(domain, max_distance)
        if return_distance:
            return [(dist, dom) for dist, dom in results if dom != domain]
        else:
            return [dom for _, dom in results if dom != domain]
    
    def get_similar_length_domains(
        self, 
        domain: str, 
        ratio: float = 0.3,
        method: str = "bktree", 
        return_distance: bool = False
    ) -> List[str]:
        if method == "bktree":
            if self._bktree:
                return self._bktree_find_similar(
                    domain=domain, 
                    max_distance=min(
                        (ratio * 10) + 1,
                        2
                    )
                )
        return self._get_similar_length_domains(domain=domain, ratio=ratio)
    
    def __contains__(self, other: str | LegitDomain):
        if isinstance(other, LegitDomain):
            domain = other.domain
        else:
            domain = other
        
        domain = str(domain).strip()
        if not domain:
            return False
        
        return self.includes(domain)
    
    def __len__(self):
        return self.get_legit_domain_count()
    
    def __getitem__(self, index: int):
        with self.get_session() as session:
            result = session.exec(
                select(LegitDomain).offset(index).limit(1)
            ).first()
            if not result:
                raise IndexError("Index out of range")
            return result.domain
    
    def __iter__(self):
        batch_size = LEGIT_BATCH_SIZE
        offset = 0
        while True:
            with self.get_session() as session:
                statement = select(LegitDomain.domain).offset(offset).limit(batch_size)
                results = session.exec(statement).all()
                if not results:
                    break
                for domain in results:
                    yield domain
                offset += batch_size
            
def chunk_insert(name: str, chunk_size: int, total: int, db: LegitDomainDBManager, data: list | tuple):
    print("Debut pour", name)
    range_object = range(0, total, chunk_size)
    total_chunk = len(range_object)
    print(total_chunk, "chunk")
    n = 1
    for i in range_object:
        print(name, "chunk", n, "/", total_chunk, "Début")
        print(db.create_legit_domain_by_lot(data[i : i + chunk_size]))
        print(name, "chunk", n, "/", total_chunk, "OK")    
        n += 1
    print(name, "FIN")
    
if __name__ == "__main__":
    import pandas as pd
    from anti_phishing_ia.core.legitimate_domain_creator import compile_all_domains
    db = LegitDomainDBManager()
    
    def build():
        D1 = compile_all_domains()
        D2 = pd.DataFrame(pd.read_csv(
            os.path.join(
                os.path.dirname(
                    __file__
                ),
                "legite_domain", "DOCS", "legit-top-1m.csv"
            )
        )).loc[:, "DOMAIN"].apply(
            lambda url: _get_domain(url, True)
        ).tolist()
        D3 = pd.DataFrame(pd.read_csv(
            os.path.join(
                os.path.dirname(
                    __file__
                ),
                "legite_domain", "DOCS", "legit-top10milliondomains.csv"
            )
        )).loc[:, "Domain"].apply(
            lambda url: _get_domain(url, True)
        ).tolist()
        CHUNK_SIZE = 1_000_000
        chunk_insert(
            name="BASE DOMAIN",
            chunk_size=CHUNK_SIZE,
            total=len(D1),
            db=db,
            data=D1
        )
        chunk_insert(
            name="TRANCO LEGIT DOMAIN",
            chunk_size=CHUNK_SIZE,
            total=len(D2),
            db=db,
            data=D2
        )
        chunk_insert(
            name="TOP 10M DOMAIN",
            chunk_size=CHUNK_SIZE,
            total=len(D3),
            db=db,
            data=D3
        )
    
    def test():
        print(db.get_legit_domain_count(), "domain en db")
        print("Google inclut ?", db.get_legit_domain("google.com"))
        print("Et Facebook ?", "xxx.com" in db)
        # print("ITER - GETITEM")
        # for i in range(4):
        #     print(db[i])
        
        # print("ITER")
        # i = 0
        # for d in db:
        #     print(d)
        #     i += 1
        #     if i > 10:
        #         break
    # build()
    test()
    
            