# Empowering B2B API Security: Enforcing Rate Limiting with BIG-IP APM and Custom iRules

## The problem: Unprotected API - Vulnerable to Overload Without Rate-Limiting Enforcement"

Our customer in the B2B sector is encountering a challenge with their public API. Despite having implemented a custom method for generating long-lived API keys, they find themselves unable to enforce rate-limiting effectively. This absence of rate-limiting mechanisms poses significant challenges, potentially resulting in the overloading of their system due to excessive requests or the exploitation of their API by unauthorized users. Without proper rate-limiting controls in place, the customer faces risks to both the performance and security of their API infrastructure, necessitating a solution to mitigate these concerns and ensure the smooth operation of their services for their customers.

## The solution: BIG-IP APM and Custom iRules for Effective Rate-Limiting

My solution involves leveraging the API Protection feature of BIG-IP APM in conjunction with a custom iRule. By utilizing this combination, our customer can effectively extract the API Keys from HTTP requests and enforce rate limiting on specific API endpoints. This approach empowers the customer to secure their SOAP API while efficiently managing and controlling access to critical endpoints, ensuring optimal performance and safeguarding against abuse or overload.

## Lab setup

For developing a solution I needed an API. Since I was at a stage of my life, where I thought learning go might be beneficial, I found a simple boilerplate in Go and adjusted it to my liking. My API is available here: [Gin API for Managing Gin Spirits](https://github.com/webserverdude/go-gin-api).

For my lab I used BIG-IP 16.1.

