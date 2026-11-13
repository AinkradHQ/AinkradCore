-- Room centroids for "closest room": per room the sum of its items' vectors and how many, plus which
-- items are in it so an item committed twice counts once. Same file, same key: this is item meaning.
CREATE TABLE room_members (
    model        TEXT NOT NULL,
    room         TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    PRIMARY KEY (model, room, content_hash)
);
CREATE TABLE room_centroids (
    model TEXT NOT NULL,
    room  TEXT NOT NULL,
    n     INTEGER NOT NULL,
    vec   BLOB NOT NULL,
    PRIMARY KEY (model, room)
);
