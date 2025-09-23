# PostgreSQL Database Image
WiseFood employs PostgreSQL as the relational database of the system to partially satisfy the storage requirements of various services. This image is based on `postgres:17.6-alpine`.

## Schemas within the wisefood database  
1. `wisefood`: The main application schema.  
2. `keycloak`: Schema used for identity and access management.  

## Users  

0. `postgres`:
    - Role: Default superuser.
    - Permissions: Root access.

1. `wisefood`:  
    - Role: Main system user.  
    - Permissions: Owner of the `wisefood` database and schemas.  

2. `keycloak`:  
    - Role: Keycloak user.  
    - Permissions: R/W access to the `keycloak` schema in the `wisefood` database.  

Refer to the script for detailed setup commands.  