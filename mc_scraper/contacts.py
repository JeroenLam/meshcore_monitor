import asyncio
from meshcore import MeshCore, EventType
from pydantic import BaseModel
from enum import Enum
from datetime import datetime
from main import mc, es, ES_INDEX


class DeviceType(Enum):
    unkown0 = 0
    client = 1
    repeater = 2
    unkown3 = 3
    unkown4 = 4


class Contact(BaseModel):
    public_key: str
    type: DeviceType
    flags: int
    out_path_len: int
    out_path: str
    adv_name: str
    last_advert: datetime
    adv_lat: float
    adv_lon: float
    lastmod: datetime

    def __str__(self) -> str:
        return (
            f"Contact(\n"
            f"  adv_name     = {self.adv_name}\n"
            f"  public_key   = {self.public_key}\n"
            f"  type         = {self.type.name}\n"
            f"  flags        = {self.flags}\n"
            f"  out_path_len = {self.out_path_len}\n"
            f"  out_path     = {self.out_path}\n"
            f"  last_advert  = {self.last_advert.isoformat()}\n"
            f"  location     = ({self.adv_lat:.6f}, {self.adv_lon:.6f})\n"
            f"  lastmod      = {self.lastmod.isoformat()}\n"
            f")"
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "public_key": self.public_key,
            "type": self.type.name,  # or self.type.value if you prefer
            "flags": hex(self.flags),
            "out_path_len": str(self.out_path_len),
            "out_path": self.out_path,
            "adv_name": self.adv_name,
            "last_advert": self.last_advert.isoformat(),
            "adv_lat": str(self.adv_lat),
            "adv_lon": str(self.adv_lon),
            "lastmod": self.lastmod.isoformat(),
        }


async def get_contacts_obj() -> list[Contact]:
    # Get your contacts
    result = await mc.commands.get_contacts()
    if result.type == EventType.ERROR:
        raise Exception(f"Error getting contacts: {result.payload}")

    contacts: dict[str, dict[str, str]] = result.payload

    # Ingest contact dict into contact object
    return [Contact(**contact) for contact in contacts.values()]


async def get_contacts() -> dict[str, dict[str, str]]:
    # Get your contacts
    result = await mc.commands.get_contacts()
    if result.type == EventType.ERROR:
        raise Exception(f"Error getting contacts: {result.payload}")

    return result.payload


async def get_contacts_by_prefix(prefix):
    contacts = await get_contacts()
    return [contact for key, contact in contacts.items() if key.startswith(prefix)]


async def get_contacts_by_name(name):
    contacts = await get_contacts()
    return [contact for contact in contacts.values() if contact["adv_name"] == name]


async def upsert_contact(
    contact: Contact,
    index: str = "meshcore_contacts",
) -> None:
    """
    Insert or update a Contact document in Elasticsearch.

    - Uses public_key as the document ID
    - Merges fields on update
    - Tracks previous adv_name values in `previous_names`
      (unique, only when the name changes)
    """
    doc = contact.to_dict()

    await es.update(
        index=index,
        id=contact.public_key,
        script={
            "lang": "painless",
            "source": """
                if (ctx._source.adv_name != null &&
                    ctx._source.adv_name != params.adv_name) {

                    if (ctx._source.previous_names == null) {
                        ctx._source.previous_names = [];
                    }

                    if (!ctx._source.previous_names.contains(ctx._source.adv_name)) {
                        ctx._source.previous_names.add(ctx._source.adv_name);
                    }
                }

                ctx._source.putAll(params);
            """,
            "params": doc,
        },
        upsert={
            **doc,
            "previous_names": [],
        },
    )


async def update_contacts_task():
    while True:
        try:
            contacts = await get_contacts_obj()

            for contact in contacts:
                await upsert_contact(contact, index=f"{ES_INDEX}_contacts")
        except Exception as e:
            print(f"Update contact task error: {e}")

        await asyncio.sleep(30 * 60)  # 30 minutes
