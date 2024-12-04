# Simple E-Commerce API

## Usage

| Method   | Endpoint          | Request                                                                                                      | Description          |
|----------|-------------------|--------------------------------------------------------------------------------------------------------------|----------------------|
| **POST** | `/v1/auth/signup` | Body: (application/json)<br/>- email: string<br/>- password: string<br/>- name?: string<br/>- image?: string | register new user    |
| **POST** | `/v1/auth/signin` | Body: (application/json)<br/>- email: string<br/>- password: string                                          | login account        |
| **GET**  | `/v1/auth/me`     | Header: <br> - Authorization?: "Bearer [your_bearer_token]"                                                  | get user information |

[//]: # (TODO: check again for signout)

[//]: # (| **POST** | `/v1/auth/signout` | Header: <br> - Authorization: "Bearer [your_bearer_token]"                                                   | logout account       |)
