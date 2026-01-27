import os
import asyncio
from elasticsearch import AsyncElasticsearch
from meshcore import MeshCore, EventType
import logging
from datetime import datetime, timezone

from parsing import parse_mc_packet

logger = logging.getLogger(__name__)

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "changeme")
ES_INDEX = os.getenv("ES_INDEX", "meshcore")

MC_HOST = os.getenv("MC_HOST", "192.168.1.225")
MC_PORT = int(os.getenv("MC_PORT", "5000"))


# --- shared helper ---
async def _handle_event(event, et: str):
    logger.info(f"{et} observed")
    data: dict[str, str] = event.payload
    data["_timestamp"] = datetime.now(timezone.utc).isoformat()
    data["_event_type"] = et
    await es.index(
        index=ES_INDEX,
        document=data,
    )


async def get_contacts(client: MeshCore) -> dict[str, dict[str, str]]:
    # Get your contacts
    result = await client.commands.get_contacts()
    if result.type == EventType.ERROR:
        raise Exception(f"Error getting contacts: {result.payload}")

    return result.payload


async def get_contacts_by_prefix(prefix):
    contacts = await get_contacts(mc)
    return [contact for key, contact in contacts.items() if key.startswith(prefix)]


async def get_contacts_by_name(name):
    contacts = await get_contacts(mc)
    return [contact for contact in contacts.values() if contact["adv_name"] == name]


payload_keys = [
    "public_key",
    "type",
    "flags",
    "out_path_len",
    "out_path",
    "adv_name",
    "last_advert",
    "adv_lat",
    "adv_lon",
    "lastmod",
]


async def _add_contact_to_event(event, contact):
    if contact != None:
        for key in contact.keys():
            event.payload[f"c_{key}"] = contact[key]
    else:
        for key in payload_keys:
            event.payload[f"c_{key}"] = "unkown"
    return event


# --- event-specific handlers ---
async def handle_new_contact(event):
    await _handle_event(event, "NEW_CONTACT")


async def handle_contact_msg_recv(event):
    contacts = await get_contacts_by_prefix(event.payload["pubkey_prefix"])
    contact = contacts[0] if len(contacts) > 0 else {}
    try:
        event.payload["user"] = contact["adv_name"]
    except:
        event.payload["user"] = "unkown"
    event.payload["message"] = event.payload["text"]
    event = await _add_contact_to_event(event, contact)
    await _handle_event(event, "CONTACT_MSG_RECV")


async def handle_channel_msg_recv(event):
    event.payload["user"] = event.payload["text"].split(":", 1)[0].strip()
    contacts = await get_contacts_by_name(event.payload["user"])
    contact = contacts[0] if len(contacts) > 0 else {}
    event.payload["message"] = event.payload["text"].split(":", 1)[1].strip()
    event = await _add_contact_to_event(event, contact)
    await _handle_event(event, "CHANNEL_MSG_RECV")


async def handle_advertisement(event):
    await _handle_event(event, "ADVERTISEMENT")


async def handle_path_update(event):
    await _handle_event(event, "PATH_UPDATE")


async def handle_ack(event):
    await _handle_event(event, "ACK")


async def handle_path_response(event):
    await _handle_event(event, "PATH_RESPONSE")


async def handle_trace_data(event):
    await _handle_event(event, "TRACE_DATA")


async def handle_raw_data(event):
    await _handle_event(event, "RAW_DATA")


async def handle_rx_log_data(event):
    payload_hex = event.payload["payload"]
    payload_b = bytes.fromhex(payload_hex)
    fields = parse_mc_packet(payload_b)
    event.payload = event.payload | fields
    await _handle_event(event, "RX_LOG_DATA")


async def check_es_ready(
    es: AsyncElasticsearch, index: str = "meshcore", retries: int = 5, delay: int = 3
):
    dummy_doc = {
        "_tmp": "health_check",
        "_timestamp": datetime.now(timezone.utc).isoformat(),
    }

    for attempt in range(1, retries + 1):
        try:
            # Try indexing a dummy document
            await es.index(index=index, document=dummy_doc)
            logger.info(f"Elasticsearch is up (dummy index successful).")
            return True
        except Exception as e:
            logger.warning(f"ES not ready (attempt {attempt}/{retries}): {e}")
            await asyncio.sleep(delay)

    logger.error(f"Elasticsearch did not become ready after {retries} attempts.")
    return False


async def main():
    global mc
    global es

    mc = await MeshCore.create_tcp(
        MC_HOST,
        MC_PORT,
        auto_reconnect=True,
        max_reconnect_attempts=5,
    )

    es = AsyncElasticsearch(
        ES_HOST,
    )

    if not await check_es_ready(es, index=ES_INDEX):
        raise RuntimeError(f"Elasticsearch is not reachable or ready: {ES_HOST}")

    mc.subscribe(EventType.NEW_CONTACT, handle_new_contact)
    mc.subscribe(EventType.CONTACT_MSG_RECV, handle_contact_msg_recv)
    mc.subscribe(EventType.CHANNEL_MSG_RECV, handle_channel_msg_recv)
    mc.subscribe(EventType.ADVERTISEMENT, handle_advertisement)
    mc.subscribe(EventType.PATH_UPDATE, handle_path_update)
    mc.subscribe(EventType.ACK, handle_ack)
    mc.subscribe(EventType.PATH_RESPONSE, handle_path_response)
    mc.subscribe(EventType.TRACE_DATA, handle_trace_data)
    mc.subscribe(EventType.RAW_DATA, handle_raw_data)
    mc.subscribe(EventType.RX_LOG_DATA, handle_rx_log_data)

    logger.info("Start listening for new packets")
    await mc.start_auto_message_fetching()

    result = await mc.commands.send_device_query()
    if result.type == EventType.ERROR:
        raise Exception(f"Error getting device info: {result.payload}")
    else:
        logger.info(f"Device connected!")
        logger.info(f"Device model: {result.payload['model']}")

    try:
        # Keep the main program running
        logger.info("Entering waiting loop")
        await asyncio.sleep(float("inf"))
    except asyncio.CancelledError:
        # Clean up when program ends
        await mc.stop_auto_message_fetching()
        await mc.disconnect()


asyncio.run(main())
