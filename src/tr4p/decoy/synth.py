"""Synthetic, multilingual company data.

Everything is invented. People are combinations of common given and family
names, companies are made-up words, e-mail uses domains reserved for
examples, addresses come from the documentation ranges, and phone numbers
use ranges set aside for fiction or an all-zero exchange that cannot be
dialled. No real customer data is ever involved.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "corp.test", "mail.invalid")
ADDRESS_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")

# locale -> (given names, family names, family name first, phone pattern, latin slug base)
_PEOPLE = {
    "en": (("Alice", "Martin", "Grace", "Owen", "Nora", "Felix", "Ruth", "Hugo"),
           ("Carver", "Whitlock", "Ellery", "Marsh", "Dunmore", "Hale"), False,
           "+1-202-555-01{n:02d}"),
    "id": (("Budi", "Siti", "Agus", "Dewi", "Rizky", "Putri", "Wahyu", "Ayu"),
           ("Santoso", "Wijaya", "Pratama", "Lestari", "Hidayat", "Kusuma"), False,
           "+62-21-0000-01{n:02d}"),
    "ar": (("أحمد", "فاطمة", "يوسف", "ليلى", "عمر", "مريم", "خالد", "نور"),
           ("الحداد", "النجار", "الخطيب", "السعدي", "الراشد", "المصري"), False,
           "+20-2-0000-01{n:02d}"),
    "ko": (("민준", "서연", "지호", "하은", "도윤", "수아", "준서", "지우"),
           ("김", "이", "박", "최", "정", "강"), True,
           "+82-2-0000-01{n:02d}"),
    "es": (("Lucía", "Mateo", "Valeria", "Diego", "Inés", "Bruno", "Elena", "Tomás"),
           ("Robledo", "Castaño", "Ferrán", "Olmedo", "Zubiri", "Paredes"), False,
           "+34-900-000-1{n:02d}"),
}
_ROLES = ("admin", "editor", "support", "billing", "viewer", "manager")
_COMPANY_HEADS = ("Nordvale", "Kestrim", "Lumora", "Tessaly", "Orbane", "Halvik", "Sablex", "Quillon")
_COMPANY_TAILS = ("Logistics", "Systems", "Trading", "Foods", "Energy", "Works", "Supply", "Labs")
_PRODUCTS = {
    "en": ("Standard plan", "Storage add-on", "Priority support", "Annual licence"),
    "id": ("Paket standar", "Tambahan penyimpanan", "Dukungan prioritas", "Lisensi tahunan"),
    "ar": ("الباقة الأساسية", "مساحة تخزين إضافية", "دعم ذو أولوية", "ترخيص سنوي"),
    "ko": ("기본 요금제", "추가 저장 공간", "우선 지원", "연간 라이선스"),
    "es": ("Plan estándar", "Almacenamiento extra", "Soporte prioritario", "Licencia anual"),
}
_POSTS = {
    "en": ("Quarterly update for our partners", "New warehouse opening next month"),
    "id": ("Pembaruan triwulan untuk mitra kami", "Gudang baru dibuka bulan depan"),
    "ar": ("التحديث الفصلي لشركائنا", "افتتاح مستودع جديد الشهر المقبل"),
    "ko": ("파트너를 위한 분기별 소식", "다음 달 새 물류 창고 개장"),
    "es": ("Novedades trimestrales para socios", "Nuevo almacén el mes que viene"),
}
LOCALES = tuple(_PEOPLE)


@dataclass(frozen=True)
class Person:
    id: int
    name: str
    login: str
    email: str
    role: str
    phone: str
    locale: str
    last_address: str


@dataclass(frozen=True)
class Order:
    id: int
    customer: str
    product: str
    amount: str
    currency: str
    status: str


class Dataset:
    """All fake records of one decoy, fixed by its seed."""

    def __init__(self, rng: random.Random, people: int = 40, orders: int = 60) -> None:
        self.companies = [f"{rng.choice(_COMPANY_HEADS)} {rng.choice(_COMPANY_TAILS)}"
                          for _ in range(12)]
        self.people = [self._person(rng, index) for index in range(1, people + 1)]
        self.orders = [self._order(rng, index) for index in range(1001, 1001 + orders)]
        self.posts = [(locale, title) for locale in LOCALES for title in _POSTS[locale]]
        rng.shuffle(self.posts)

    @staticmethod
    def _person(rng: random.Random, index: int) -> Person:
        locale = LOCALES[index % len(LOCALES)] if index > 3 else "en"
        given_names, family_names, family_first, phone = _PEOPLE[locale]
        given, family = rng.choice(given_names), rng.choice(family_names)
        name = f"{family}{given}" if family_first else f"{given} {family}"
        login = f"user{index:03d}"
        return Person(
            id=index, name=name, login=login,
            email=f"{login}@{rng.choice(EMAIL_DOMAINS)}",
            role="admin" if index == 1 else rng.choice(_ROLES[1:]),
            phone=phone.format(n=rng.randrange(100)), locale=locale,
            last_address=f"{rng.choice(ADDRESS_PREFIXES)}{rng.randrange(1, 255)}",
        )

    def _order(self, rng: random.Random, index: int) -> Order:
        person = rng.choice(self.people)
        return Order(
            id=index, customer=person.name, product=rng.choice(_PRODUCTS[person.locale]),
            amount=f"{rng.randrange(20, 5000)}.{rng.randrange(100):02d}",
            currency=rng.choice(("USD", "EUR", "IDR", "KRW", "EGP")),
            status=rng.choice(("paid", "pending", "refunded", "shipped")),
        )

    def value_for(self, rng: random.Random, column: str, kind: str) -> object:
        """A synthetic value for a column of an imported schema, chosen from
        the column's name and type only."""
        name, kind = column.lower(), kind.lower()
        person = rng.choice(self.people)
        if "mail" in name:
            return person.email
        if "phone" in name or "mobile" in name:
            return person.phone
        if "name" in name or "user" in name or "login" in name:
            return person.name
        if "ip" in name.split("_") or "addr" in name:
            return person.last_address
        if "pass" in name or "hash" in name or "secret" in name or "token" in name:
            return "".join(rng.choice("abcdef0123456789") for _ in range(40))
        if "int" in kind or "serial" in kind or name == "id" or name.endswith("_id"):
            return rng.randrange(1, 100000)
        if "bool" in kind:
            return rng.random() < 0.5
        if "dec" in kind or "num" in kind or "float" in kind or "double" in kind or "real" in kind:
            return round(rng.uniform(1, 9999), 2)
        if "date" in kind or "time" in kind:
            return f"202{rng.randrange(3, 6)}-{rng.randrange(1, 13):02d}-{rng.randrange(1, 29):02d}"
        return rng.choice(self.companies)
