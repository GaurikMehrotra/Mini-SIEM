"""Sensor context links using community ID or bidirectional tuple/time fallback."""

from minisiem.store.db import Store


def link(store: Store, seconds: int = 60) -> int:
    """Link only Zeek to Suricata records; IDs never imply an attack."""
    with store.transaction():
        return store.db.execute(
            """INSERT OR IGNORE INTO links
        SELECT a.id,b.id, CASE WHEN a.community_id=b.community_id THEN 'community_id' ELSE 'tuple_window' END
        FROM events a JOIN events b ON
          a.dataset LIKE 'suricata.%' AND b.dataset LIKE 'zeek.%'
          AND ABS((julianday(a.timestamp)-julianday(b.timestamp))*86400)<=?
          AND (a.community_id=b.community_id OR
           (a.transport=b.transport AND
            ((a.source_ip=b.source_ip AND a.destination_ip=b.destination_ip AND a.source_port=b.source_port AND a.destination_port=b.destination_port)
             OR (a.source_ip=b.destination_ip AND a.destination_ip=b.source_ip AND a.source_port=b.destination_port AND a.destination_port=b.source_port))))""",
            (seconds,),
        ).rowcount
