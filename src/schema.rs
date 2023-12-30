

use diesel::table;

extern crate diesel;

diesel::table! {
    users (id) {
        id -> Integer,
        email -> Text,
        key -> Text,
        vault -> Text,
    }
}