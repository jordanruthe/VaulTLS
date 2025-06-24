use std::{env, fs};
use std::path::Path;
use rusqlite::fallible_iterator::FallibleIterator;
use std::str::FromStr;
use anyhow::anyhow;
use argon2::password_hash::PasswordHashString;
use rusqlite::{params, Connection, Result};
use include_dir::{include_dir, Dir};
use rusqlite_migration::Migrations;
use crate::{ApiError, Certificate, User};
use crate::constants::{DB_FILE_PATH, TEMP_DB_FILE_PATH};
use crate::data::enums::UserRole;

static MIGRATIONS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/migrations");

pub(crate) struct VaulTLSDB {
    connection: Connection
}

impl VaulTLSDB {
    pub(crate) fn new(db_encrypted: bool) -> anyhow::Result<Self> {
        // The next two lines are for backward compatability and should be removed in a future release
        let db_path = Path::new(DB_FILE_PATH);
        let db_initialized = db_path.exists();

        let mut connection = Connection::open(DB_FILE_PATH)?;
        let db_secret = Self::get_db_secret();
        println!("DB secret: {:?}", db_secret);
        if db_encrypted {
            if let Ok(ref db_secret) = db_secret {
                connection.pragma_update(None, "key", db_secret)?;
            } else {
                return Err(anyhow!("VAULTLS_DB_SECRET missing".to_string()));
            }

        }
        connection.pragma_update(None, "foreign_keys", &"ON")?;
        // This if statement can be removed in a future version
        if db_initialized {
            let user_version: i32 = connection
                .query_one("SELECT user_version FROM pragma_user_version", [], |row| row.get(0))
                .expect("Failed to get PRAGMA user_version");
            // Database already initialized, update user_version to 1
            if user_version == 0 {
                connection.pragma_update(None, "user_version", &"1")?;
            }
        }
        
        Self::migrate_database(&mut connection)?;

        if !db_encrypted {
            if let Ok(ref db_secret) = db_secret {
                println!("Migrating to encrypted database");
                Self::create_encrypt_db(&connection, db_secret)?;
                drop(connection);
                let conn = Self::migrate_to_encrypted_db(&db_secret)?;
                return Ok(Self { connection: conn});
            }
        }

        Ok(Self { connection})
    }

    /// Create a new encrypted database with cloned data
    fn create_encrypt_db(conn: &Connection, new_db_secret: &str) -> Result<()> {
        let encrypted_path = TEMP_DB_FILE_PATH;
        conn.execute(
            &format!("ATTACH DATABASE '{}' AS encrypted KEY '{}';", encrypted_path, new_db_secret),
            [],
        )?;

        // Migrate data
        conn.query_row("SELECT sqlcipher_export('encrypted');", [], |_row| Ok(()))?;
        // Copy user_version for migrations
        let user_version: Result<i64> = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0));
        if let Ok(user_version) = user_version {
            conn.execute(
                &format!("PRAGMA encrypted.user_version = '{}';", user_version),
                []
            )?;
        }

        conn.execute("DETACH DATABASE encrypted;", [])?;
        Ok(())
    }
    
    /// Migrate the unencrypted database to an encrypted database
    fn migrate_to_encrypted_db(db_secret: &str) -> anyhow::Result<Connection> {
        fs::remove_file(DB_FILE_PATH)?;
        fs::rename(TEMP_DB_FILE_PATH, DB_FILE_PATH)?;
        let conn = Connection::open(DB_FILE_PATH)?;
        conn.pragma_update(None, "key", db_secret)?;
        conn.pragma_update(None, "foreign_keys", &"ON")?;
        Ok(conn)
    }

    fn migrate_database(conn: &mut Connection) -> Result<()> {
        let migrations = Migrations::from_directory(&MIGRATIONS_DIR).expect("Failed to load migrations");
        migrations.to_latest(conn).expect("Failed to migrate database");

        Ok(())
    }

    /// Insert a new CA certificate into the database
    /// Adds id to the Certificate struct
    pub(crate) fn insert_ca(
        &self,
        ca: &mut Certificate
    ) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "INSERT INTO ca_certificates (created_on, valid_until, certificate, key) VALUES (?1, ?2, ?3, ?4)",
            params![ca.created_on, ca.valid_until, ca.cert, ca.key],
        )?;
        
        ca.ca_id = self.connection.last_insert_rowid();

        Ok(())
    }

    /// Retrieve the most recent CA entry from the database
    pub(crate) fn get_current_ca(&self) -> Result<Certificate, ApiError> {
        let mut stmt = self.connection.prepare("SELECT * FROM ca_certificates ORDER BY id DESC LIMIT 1")?;

        stmt.query_row([], |row| {
            Ok(Certificate{
                id: row.get(0)?,
                created_on: row.get(1)?,
                valid_until: row.get(2)?,
                cert: row.get(3)?,
                key: row.get(4)?,
                ..Default::default()
            })
        }).map_err(|_| ApiError::BadRequest("VaulTLS has not been set-up yet".to_string()))
    }

    /// Retrieve all user certificates from the database
    /// If user_id is Some, only certificates for that user are returned
    /// If user_id is None, all certificates are returned
    pub(crate) fn get_all_user_cert(&self, user_id: Option<i64>) -> Result<Vec<Certificate>, rusqlite::Error>{
        let query = match user_id {
            Some(_) => "SELECT id, name, created_on, valid_until, pkcs12, pkcs12_password, user_id FROM user_certificates WHERE user_id = ?1",
            None => "SELECT id, name, created_on, valid_until, pkcs12, pkcs12_password, user_id FROM user_certificates"
        };
        let mut stmt = self.connection.prepare(query)?;
        let rows = match user_id {
            Some(id) => stmt.query(params![id])?,
            None => stmt.query([])?,
        };
        rows.map(|row| {
                Ok(Certificate {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_on: row.get(2)?,
                    valid_until: row.get(3)?,
                    pkcs12: row.get(4)?,
                    pkcs12_password: row.get(5).unwrap_or_default(),
                    user_id: row.get(6)?,
                    ..Default::default()
                })
            })
            .collect()
    }

    /// Retrieve the certificate's PKCS12 data with id from the database
    /// Returns the id of the user the certificate belongs to and the PKCS12 data
    pub(crate) fn get_user_cert_pkcs12(&self, id: i64) -> Result<(i64, String, Vec<u8>), rusqlite::Error> {
        let mut stmt = self.connection.prepare("SELECT user_id, name, pkcs12 FROM user_certificates WHERE id = ?1")?;

        stmt.query_row(
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
    }

    /// Retrieve the certificate's PKCS12 data with id from the database
    /// Returns the id of the user the certificate belongs to and the PKCS12 password
    pub(crate) fn get_user_cert_pkcs12_password(&self, id: i64) -> Result<(i64, String), rusqlite::Error> {
        let mut stmt = self.connection.prepare("SELECT user_id, pkcs12_password FROM user_certificates WHERE id = ?1")?;
        
        stmt.query_row(
            params![id],
            |row| Ok((row.get(0)?, row.get(1).unwrap_or_default())),
        )
    }

    /// Insert a new certificate into the database
    /// Adds id to Certificate struct
    pub(crate) fn insert_user_cert(&self, cert: &mut Certificate) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "INSERT INTO user_certificates (name, created_on, valid_until, pkcs12, pkcs12_password, ca_id, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![cert.name, cert.created_on, cert.valid_until, cert.pkcs12, cert.pkcs12_password, cert.ca_id, cert.user_id],
        )?;
        
        cert.id = self.connection.last_insert_rowid();

        Ok(())
    }

    /// Delete a certificate from the database
    pub(crate) fn delete_user_cert(&self, id: i64) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "DELETE FROM user_certificates WHERE id=?1",
            params![id]
        )?;

        Ok(())
    }

    /// Add a new user to the database
    pub(crate) fn add_user(&self, user: &mut User) -> Result<(), ApiError> {
        self.connection.execute(
            "INSERT INTO users (name, email, password_hash, oidc_id, role) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![user.name, user.email, user.password_hash.clone().map(|hash| hash.to_string()), user.oidc_id, user.role as u8],
        )?;

        user.id = self.connection.last_insert_rowid();
        Ok(())
    }

    /// Delete a user from the database
    pub(crate) fn delete_user(&self, id: i64) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "DELETE FROM users WHERE id=?1",
            params![id]
        )?;

        Ok(())
    }

    /// Update a user in the database
    pub(crate) fn update_user(&self, user: &User) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "UPDATE users SET name = ?1, email =?2 WHERE id=?3",
            params![user.name, user.email, user.id]
        )?;

        Ok(())
    }

    /// Return a user entry by id from the database
    pub(crate) fn get_user(&self, id: i64) -> Result<User, rusqlite::Error> {
        self.connection.query_row(
            "SELECT id, name, email, password_hash, oidc_id, role FROM users WHERE id=?1",
            params![id],
            |row| {
                let hash: Option<String> = row.get(3)?;
                let hash_string = match hash {
                    Some(hash) => PasswordHashString::from_str(hash.as_str()).ok(),
                    None => None
                };
                let role_number: u8 = row.get(5)?;
                Ok(User {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    email: row.get(2)?,
                    password_hash: hash_string,
                    oidc_id: row.get(4)?,
                    role: UserRole::try_from(role_number).unwrap(),
                })
            }
        )
    }

    /// Return a user entry by email from the database
    pub(crate) fn get_user_by_email(&self, email: &str) -> Result<User, ApiError> {
        self.connection.query_row(
            "SELECT id, name, email, password_hash, oidc_id, role FROM users WHERE email=?1",
            params![email],
            |row| {
                let hash: String = row.get(3)?;
                let role_number: u8 = row.get(5)?;
                Ok(User {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    email: row.get(2)?,
                    password_hash: PasswordHashString::from_str(hash.as_str()).ok(),
                    oidc_id: row.get(4)?,
                    role: UserRole::try_from(role_number).map_err(|_| rusqlite::Error::QueryReturnedNoRows)?,
                })
            }
        ).map_err(|_| ApiError::Database(rusqlite::Error::QueryReturnedNoRows))
    }

    /// Return all users from the database
    pub(crate) fn get_all_user(&self) -> Result<Vec<User>, rusqlite::Error>{
        let mut stmt = self.connection.prepare("SELECT id, name, email, role FROM users")?;
        let query = stmt.query([])?;
        query.map(|row| {
                Ok(User {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    email: row.get(2)?,
                    password_hash: None,
                    oidc_id: None,
                    role: row.get(3)?
                })
            })
            .collect()
    }

    /// Set a new password for a user
    /// The password needs to be hashed already
    pub(crate) fn set_user_password(&self, id: i64, password_hash: &String) -> Result<(), ApiError> {
        self.connection.execute(
            "UPDATE users SET password_hash = ?1 WHERE id=?2",
            params![password_hash, id]
        )?;

        Ok(())
    }

    /// Register a user with an OIDC ID:
    /// If the user does not exist, a new user is created.
    /// If the user already exists and has matching OIDC ID, nothing is done.
    /// If the user already exists but has no OIDC ID, the OIDC ID is added.
    /// If the user already exists but has a different OIDC ID, an error is returned.
    /// The function adds the user id and role to the User struct
    pub(crate) fn register_oidc_user(&self, user: &mut User) -> Result<(), ApiError> {
        let existing_oidc_user_option: Option<(i64, UserRole)> = self.connection.query_row(
            "SELECT id, role FROM users WHERE oidc_id=?1",
            params![user.oidc_id],
            |row| Ok((row.get(0)?, row.get(1)?))
        ).ok();

        if let Some(existing_oidc_user) = existing_oidc_user_option {
            // User with the correct OIDC_ID exists
            user.id = existing_oidc_user.0;
            user.role = existing_oidc_user.1;
            Ok(())
        } else {
            // User with the correct OIDC_ID does not exist
            let existing_local_user_option = self.connection.query_row(
                "SELECT id, oidc_id, role FROM users WHERE email=?1",
                params![user.email],
                |row| {
                    let id = row.get(0)?;
                    let oidc_id: Option<String> = row.get(1)?;
                    let role = row.get(2)?;
                    Ok((id, oidc_id, role))
                }
            ).ok();
            if let Some(existing_local_user_option) = existing_local_user_option {
                // Local user account exists
                if existing_local_user_option.1.is_some() {
                    // Local user account has already a different OIDC_ID
                    Err(ApiError::Unauthorized(Some("OIDC Subject ID mismatch".to_string())))
                } else {
                    // Local user account does not have a OIDC_ID
                    self.connection.execute(
                        "UPDATE users SET oidc_id = ?1 WHERE id=?2",
                        params![user.oidc_id, existing_local_user_option.0]
                    )?;
                    user.id = existing_local_user_option.0;
                    user.role = existing_local_user_option.2;
                    Ok(())
                }
            } else {
                // Local user account does not exist
                self.add_user(user)
            }
        }
    }

    /// Check if the database is setup
    /// Returns true if the database contains at least one user
    /// Returns false if the database is empty
    pub(crate) fn is_setup(&self) -> bool {
        self.connection.query_row(
            "SELECT id FROM users",
            [],
            |_| Ok(())
        ).is_ok()
    }

    // Get database secret
    fn get_db_secret() -> Result<String, Box<dyn std::error::Error>> {
        let val = env::var("VAULTLS_DB_SECRET")?;
        println!("VAULTLS_DB_SECRET: {}", val);
    
        // If the var starts with "/run/secrets/", treat it as a file path
        if val.starts_with("/run/secrets/") {
            let contents = fs::read_to_string(val)?.trim().to_string();
            println!("Contents: {}", contents);
            Ok(contents)
        } else {
            println!("Val: {}", val);
            Ok(val)
        }
    }
}