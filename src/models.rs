use diesel::queryable;

frontend::models

pub struct User {
    pub id: i32,
    pub email: String,
    pub key: String,
    pub vault: String,
}

#[derive(Insertable)]
#[table_name = "users"]
pub struct NewUser {
    pub email: String,
    pub key: String,
    pub vault: String,
}