---
layout: blog_post
title: "Nano Blogging Service with Ktor and Okta OAuth2"
author: ruslan-zaharov
by: contractor
communities: [java]
description: ""
tags: []
tweets:
- ""
- ""
- ""
image:
type: awareness|conversion
---

# Create a Secured Ktor Application with Kotlin

 
In this tutorial, you will build your very own Nano Blogging Service(**nabl** for short) using a modern JVM stack with Kotlin programming language using Ktor web framework and secure it with Okta. Users can log in or sign up, post updates and browse specific or global _chronological_ feed without _advertisement_.
Blogging service displays posts from the selected user or everyone in the _chronological_ feed. Users can log in or sign up, post updates.


Kotlin is often considered as a "better Java" and often become an easy, efficient substitution mainly because it has great interoperability with Java. That allows you to employ the largest ecosystem of existing JVM frameworks and libraries written and designed for Java in your Kotlin application and vice-versa. Kotlin works well with [Spring Boot](okta-spring-boot), Jersey, Dropwizard and other. "Kotlin-native" frameworks provide first-class language support, provide additional type safety not available in the Java world and often give competitive advantages.
 
[Ktor](ktor-website) is one of the most prominent "Kotlin-native" webserver frameworks officially supported by JetBrains, creators of Kotlin language and IntelliJ IDEA. It's an unopinionated highly-customizable modular framework that gives developers full control over implementation while providing sensible defaults.
 
 
**Requirements**
 
* Computer with installed JVM, git, bash-like command line
* Familiarity with Java or Kotlin
* Your favorite IDE, for instance, IntelliJ IDEA Community Edition
* Free [Okta Developer account](okta-signup)
* 15 mins of your time
 
 
### Build a Ktor Application
 
As with any web application framework, Ktor provides several libraries and imposes some conventions. Don't worry; it doesn't tell you how to write your code. The conventions are mostly for the HTTP layer, and you're free to write other lower layers the way you want. Few most notable things include:
 
* The web application is a pipeline processing incoming request through _features_ and _route handlers_.
* Request handling is non-blocking; it relies on [Kotlin coroutines](kotlin-coroutines).
* The configuration file format is [HOCON](hocon).
* Framework is employing DSL for the top-level declarations, e.g. modules setup, routing, etc.
* Pluggable features are configured using `install(FeatureObject) { config }`.
* Most of the functions and properties you use are [extension functions](kotlin-extension-functions).
 
### Nano Blogging Service Project Structure

Your application depends on several libraries:
 
* **Kotlin** programming language you use for this project
* **Ktor server** with **Ktor server CIO** - server implementation and coroutine-based HTTP engine core
* **Ktor client** with **Ktor client CIO** - client used to communicate to OAuth2 server
* **Ktor Auth** module to handle authorization flow
* **kotlinx.html** set of classes allowing to write type-safe HTML generators
* **Okta JWT Verifier** library helps to parse and verify access and id tokens
 

Bootstrap project by cloning out git repository and switching to the `initial` tag:
 
```
$ git checkout git@github.com:ruXlab/okta-ktor-nano-blogging-service.git
$ cd okta-ktor-nano-blogging-service
$ git checkout tag
```
 
 
**Data Layer**
 
Look at the basic data models in your application in `entities.kt` file:
 
```kotlin
package com.okta.demo.ktor
 
import java.time.LocalDateTime
 
data class BlogRecord(
   val userHandle: String,
   val text: String,
   val createdAt: LocalDateTime = LocalDateTime.now()
)
 
data class UserSession(
   val username: String,
   val idToken: String
)
```
 
`BlogRecord` contains information about the `userHandle`, posted `text` and `createdAt` timestamp. `UserSession` is an object which contains information about currently signed in user, see the authentication section for more details.
 
Class `BlogRecordRepositry` is responsible for data manipulation. For the demo purpose data is stored in the memory and initialized with some dummy records at startup time. Your data repository is in `BlogRecordRepository.kt` file:
 
```kotlin
package com.okta.demo.ktor
 
class BlogRecordRepository {
   private val records = mutableListOf<BlogRecord>()
 
   val all: List<BlogRecord>
       get() = records
 
   fun insert(userHandle: String, text: String) {
       records += BlogRecord(userHandle, text)
   }
 
   fun byUser(userHandle: String)
       = records.filter { it.userHandle == userHandle }
}
 
// Shared "database" instance
val blogRecords = BlogRecordRepository().apply {
   insert("kack", "Hello world!")
   insert("kack", "Keep messages short and sweet! 💬")
   insert("ann", "OMG it's a future unikorn 🦄!")
   insert("rux", "Chronological feed! It's just like the good old days! ")
   insert("kotlin", "Wise language selection")
   insert("whitestone", "We'd like to invest 💰💰💰")
   insert("cat", "🐈🐱🙀😼😻🐾")
}
```
 
### Main Application Configuration
 
Before you get into the route handling and log in flow, web service itself needs to be configured. As per convention, Ktor service is configured by creating an `Application.module()` extension function. Look at the configuration sections in `application.kt`:
 
```kotlin
package com.okta.demo.ktor
 
import io.ktor.application.*
import io.ktor.features.*
import io.ktor.request.*
import io.ktor.sessions.*
import io.ktor.util.*
import org.slf4j.event.Level
import kotlin.collections.set
 
fun main(args: Array<String>): Unit = io.ktor.server.cio.EngineMain.main(args)
 
@Suppress("unused") // Referenced in application.conf
@kotlin.jvm.JvmOverloads
fun Application.module(testing: Boolean = false) {
   // We use sessions stored in encrypted cookies
   install(Sessions) {
       cookie<UserSession>("MY_SESSION") {
           val secretEncryptKey = hex("00112233445566778899aabbccddeeff")
           val secretAuthKey = hex("02030405060708090a0b0c")
           cookie.extensions["SameSite"] = "lax"
           cookie.httpOnly = true
           transform(SessionTransportTransformerEncrypt(secretEncryptKey, secretAuthKey))
       }
   }
 
   // Respond for HEAD verb
   install(AutoHeadResponse)
 
   // Load each request
   install(CallLogging) {
       level = Level.INFO
       filter { call -> call.request.path().startsWith("/") }
   }
 
   // Configure ktor to use OAuth and register relevant routes
   setupAuth()
 
   // Register application routes
   setupRoutes()
}
 
 
// Shortcut for the current session
val ApplicationCall.session: UserSession?
   get() = sessions.get<UserSession>()
 
```
 
Your application module configures the session handler to keep data in encrypted cookies, enabling logging, which is very useful for  debugging. Two of your functions - `setupAuth()` and `setupRoutes()` configure OAuth 2.0 and setup web service routes.
 
### Service Routes
 
Your application registers two routes, with Ktor DSL makes it very expressive:
 
* `POST /` takes a `text` parameter from the body and current `actor`(user handle) from the session and creates a new nano blog record. Both `actor` and `text` must be valid to create a new record; otherwise, an error will be thrown. Upon a successful insertion, the user gets redirected to the `/`.
* `GET /{username?}` effectively handles all `GET` requests and attempts to extract the `username` URL parameter if present. Then, it renders the main template with either global or requested user's feed using `feedPage()` component.
 
See `routes.kt`
 
```kotlin
package com.okta.demo.ktor
 
import io.ktor.application.*
import io.ktor.html.*
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.routing.*
 
fun Application.setupRoutes() = routing {
   post("/") { root ->
       val actor = call.session?.username
           ?: throw Exception("User must be logged in first")
       val text = call.receiveParameters()["text"]?.takeIf(String::isNotBlank)
           ?: throw Exception("Invalid request - text must be provided")
 
       blogRecords.insert(actor, text)
 
       call.respondRedirect("/")
   }
 
   get("/{username?}") {
       val username = call.parameters["username"]
       call.respondHtmlTemplate(MainTemplate(call.session?.username)) {
           content {
               val canSendMessage = call.session != null
               if (username == null) feedPage("🏠 Home feed", blogRecords.all, canSendMessage)
               else feedPage("👤 ${username}'s blog", blogRecords.byUser(username), canSendMessage)
           }
       }
   }
}
```

Page-render function `feedPage()` takes three parameters: page title, list of the nano blog posts to render and boolean flag `canSendMessage`, if it's true the text submission form will be visible. The variable `canSendMessage` is set to true only when the current user has an active session, that is possible only after login.

### Type-Safe Views
 
Kotlin syntax empowers developers to create type-safe DSL. Your Nano Blogging Service is using the `kotlinx.html` library, which provides HTML-like syntax for HTML-rendering. All the views are placed in the `views.kt` file.
 
The primary and only template `MainTemplate` includes Bootstrap CSS library, renders top navbar menu and provides a basic layout of the frontend:
 
```kotlin
/**
* Generic web page template, contains content placeholder where
* content should be placed
*/
class MainTemplate(private val currentUsername: String? = null) : Template<HTML> {
   val content = Placeholder<HtmlBlockTag>()
   override fun HTML.apply() {
       head {
           title { +"Nano Blogging Service" }
           styleLink("https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css")
           meta(name = "viewport", content = "width=device-width, initial-scale=1, shrink-to-fit=no")
           meta(charset = "utf-8")
       }
       body("d-flex flex-column h-100") {
           header {
               div("navbar navbar-dark bg-dark shadow-sm") {
                   div("container") {
                       a(href = "/", classes = "font-weight-bold navbar-brand") {
                           +"📝 𝓝𝓐𝓝𝓞 𝓑𝓛𝓞𝓖𝓖𝓘𝓝𝓖 𝓢𝓔𝓡𝓥𝓘𝓒𝓔"
                       }
                       div("navbar-nav flex-row") {
                           if (currentUsername != null) {
                               a(href = "/${currentUsername}", classes = "nav-link mr-4") {
                                   +"Hello, $currentUsername"
                               }
                               a(href = "/logout", classes = "nav-link") {
                                   +"Logout"
                               }
                           } else {
                               div("navbar-text mr-4") {
                                   +"Hello, Guest"
                               }
                               div("navbar-item") {
                                   a(href = "/login", classes = "nav-link") {
                                       +"Login"
                                   }
                               }
                           }
                       }
 
                   }
               }
           }
           main("flex-shrink-0 mt-3") {
               div("container col-xs-12 col-lg-8") {
                   insert(content)
               }
           }
       }
   }
}
```

Confused about plus(`+`) sign in front of the string inside HTML elements? Don't worry, it's just a shortcut for the `text()` function, which sets current tag content.

View blocks such as `feedBlock()`, `sendMessageForm()` and `feedPage()` are extension functions(I know, too many of them!) on `FlowContent`. That prevents global scope pollution with enormous HTML DSL elements and provides better encapsulation.
 
```kotlin
/**
* Displays feed block only
*/
fun FlowContent.feedBlock(feedItems: List<BlogRecord>) {
   feedItems.forEach { record ->
       div("entity card m-4") {
           div("w-100 card-header") {
               h4("user font-weight-bold mb-0 pb-0 d-inline-block") {
                   a(href = "/${record.userHandle}") { +record.userHandle }
               }
               span("float-right text-secondary") {
                   +record.createdAt.format(timeFormatter)
               }
           }
           div("card-body") {
               h5 { +record.text }
           }
       }
   }
}
 
/**
* Renders send message form
*/
fun FlowContent.sendMessageForm() {
   form("/", encType = applicationXWwwFormUrlEncoded, method = post) {
       div("mb-3") {
           div("input-group") {
               input(classes = "form-control", name = "text") {
                   placeholder = "Your nano message"
                   required = true
               }
               div("input-group-append") {
                   button(classes = "btn btn-success") { +"Send! 🚀" }
               }
           }
       }
   }
}
 
/**
* Renders feed page with given title and records
*/
fun FlowContent.feedPage(title: String, records: List<BlogRecord>, canPostMessage: Boolean) {
   if (canPostMessage)
       sendMessageForm()
 
   hr { }
   h2("text-center") { +title }
   feedBlock(records.sortedByDescending(BlogRecord::createdAt))
}
```
 
 
### Start your application
 
Use IntelliJ runner or type `./gradlew run` in the command line to start your application, point your web browser to `localhost:8080`.
 
{% img blog/ktor-nano-blogging-service/website-view-for-guest.png alt:"Web application running in the guest mode" width:"828" %}{: .center-image }
 
All the messages displayed are from the in-memory database. Note that at this stage the user can't log in; hence it can't post messages. The `sendMessageForm` function is not rendering form because the current user doesn't have a session. After all, wq didn't sign in.
 
## Secure Your Ktor Website with Okta
 
Real-world applications often require users to log in to perform some actions or access information. User management and security are much more complex than it might seem; it is really hard to make it right. If you have done that previously you know what I'm talking about.
 
User management does not have to take much of your time because that problem must be solved already, right? In this tutorial, you'll be using Okta Oauth 2.0 authorization service along with OIDC, but Okta provides many features for both enterprise and personal project needs - MFA, SAML, groups, policies, social media logins, and many more. We provide solutions for different companies size - from pet projects just for yourself to big enterprises such as FedEx, Box, HubSpot, Experian, and [many others](okta-customers). Okta helps developers to implement secure authentication, handles authorization and can act as an identity provider with a minimum effort and just a dozen lines of code.
 
If you haven't created an Okta account yet, [sign up](okta-signup) first. It's free, no credit card required.
 
Login to the Okta admin console. On the top menu select **Applications** → **Add Application**:
 
{% img blog/ktor-nano-blogging-service/okta-create-new-web-application.png alt:"Create a new application screen on Okta website" width:"1110" %}{: .center-image }
 
Then, configure your Okta application. Don't worry; if you want to change anything; it's always possible to return to this screen. At very least, you need to set the following settings:
 
* **Name** - give it a meaningful name, for instance, `My Ktor nano Blogging Service`
* **Base URIs** - put `http://localhost:8080/` there. Multiple URI can be provided; you can add more URIs if needed.
* **Login redirect URIs** - set it to `http://localhost:8080/login/authorization-callback`. Upon successful login, the user will be redirected to URI provided with tokens in the query.
* **Logout redirect URIs** - value `http://localhost:8080` allows you to provide a redirect URL on successful logout.
 
And hit **Done** to finish the initial setup.
 
{% img blog/ktor-nano-blogging-service/okta-configure-application-for-ktor.png alt:"Configure your Okta application to work with Ktor Auth module" width:"924" %}{: .center-image }
 
Take note of three values you'll be using in your Ktor application:
 
 
* **Org URL**: Hover over **API** on the top menu bar, and select **Authorization Servers** menu item, copy a value from **Issuer URI**
* **Client ID** and **Client Secret** as below:
   {% img blog/ktor-nano-blogging-service/okta-client-id-and-client-secret.png alt:"Take a note of clientId and clientSecret" width:"740" %}{: .center-image }
 
## Configure Ktor OAuth 2.0 Module
 
Ktor has an implementation of Auth Client; it just needs to be configured.
 
It's always good practice to never insert any keys, tokens or credentials directly into the code. **Even for the demo project.** To inject Okta parameters from the environment variables append a new block in `resources/application.conf`:
 
```hocon
...
 
okta {
   orgUrl = ${OKTA_ORGURL}
   clientId = ${OKTA_CLIENT_ID}
   clientSecret = ${OKTA_CLIENT_SECRET}
}
```
 
To start your application from the IntelliJ IDEA or any other IDE these environment variables must be provided. In **Run/Debug Configuration** dialog click on the **Environment variables** and provide them as on the screenshot:
 
{% img blog/ktor-nano-blogging-service/intellj-idea-provide-env-variables-for-okta.png alt:"Take a note of clientId and clientSecret" width:"590" %}{: .center-image }
 
Then, create a `src/auth-settings.kt` file which will contain all okta-configuration related functions.
 
**Add a generic configuration class for Okta services.**
 
```kotlin
data class OktaConfig(
   val orgUrl: String,
   val clientId: String,
   val clientSecret: String,
   val audience: String
) {
   val accessTokenUrl = "$orgUrl/v1/token"
   val authorizeUrl = "$orgUrl/v1/authorize"
   val logoutUrl = "$orgUrl/v1/logout"
}
```
 
**Create a configuration reader**. It takes `Config` object, extracts and produces the configuration object.
 
```kotlin
fun oktaConfigReader(config: Config): OktaConfig = OktaConfig(
   orgUrl = config.getString("okta.orgUrl"),
   clientId = config.getString("okta.clientId"),
   clientSecret = config.getString("okta.clientSecret"),
   audience = config.tryGetString("okta.audience") ?: "api://default"
)
```
 
Finally, [Ktor Auth module](ktor-auth-docs) is expecting configuration to be passed as `OAuthServerSettings.OAuth2ServerSettings`, for that you need a mapping function:
 
```kotlin
fun OktaConfig.asOAuth2Config(): OAuthServerSettings.OAuth2ServerSettings =
   OAuthServerSettings.OAuth2ServerSettings(
       name = "okta",
       authorizeUrl = authorizeUrl,
       accessTokenUrl = accessTokenUrl,
       clientId = clientId,
       clientSecret = clientSecret,
       defaultScopes = listOf("openid", "profile"),
       requestMethod = Post
   )
```
 
 
## Setup Authentication Module
 
All authentication configuration and handling happen inside the `setupAuth()` function of `auth.kt` file. Start filling it with configuration. Use `oktaConfigReader()` to read configuration from the application file. Then, install `Authentication` feature and configure it to use **OAuth**, providing it redirect callback, Okta OAuth2 configuration and a default `HttpClient` for the Ktor OAuth client features.
 
```kotlin
package com.okta.demo.ktor
 
import com.typesafe.config.ConfigFactory
import com.okta.jwt.JwtVerifiers
import io.ktor.application.*
import io.ktor.auth.*
import io.ktor.client.*
 
fun Application.setupAuth() {
   val oktaConfig = oktaConfigReader(ConfigFactory.load() ?: throw Exception("Could not load config"))
 
   install(Authentication) {
       oauth {
           urlProvider = { "http://localhost:8080/login/authorization-callback" }
           providerLookup = { oktaConfig.asOAuth2Config() }
           client = HttpClient()
       }
   }
 
}
```
 
To ensure that tokens provided are valid they need to be verified, it could be done using [okta-jwt-verifier library](okta-jwt-verifier. Construct token and id verifiers as follows:
 
```kotlin
   val accessTokenVerifier = JwtVerifiers.accessTokenVerifierBuilder()
       .setAudience(oktaConfig.audience)
       .setIssuer(oktaConfig.orgUrl)
       .build()
 
 
   val idVerifier = JwtVerifiers.idTokenVerifierBuilder()
       .setClientId(oktaConfig.clientId)
       .setIssuer(oktaConfig.orgUrl)
       .build()
 
```
 
Then configure three login-specific endpoints. Ktor DSL assumes following structure:
 
```kotlin
fun Application.setupAuth() {
 
   ...
 
   routing {
       authenticate {
           // Okta calls this endpoint providing accessToken along with requested idToken
           get("/login/authorization-callback") {
               // ⚫ handle authorization
           }
 
           // When guest accessing /login it automatically redirects to okta login page
           get("/login") {
               // ⚫ perfom login
           }
       }
 
       // Perform logout by cleaning cookies
       get("/logout") {
           // ⚫ perform logout
       }
   }
}
```
 
**Sign in with `/login` endpoint**
 
It's the easiest one. Ktor will require user authentication for all endpoints located within the `authenticate` block. If a user is not authenticated, it will be redirected to the **authorization** URL. Indeed, its value is taken from the `authorizeUrl` property from `OktaConfig`.
Since it's Ktor Auth module is handling this itself the implementation would be a single line. Condition checks if a visitor has a session and if so, redirect it to the root of the website:
 
```kotlin
// When guest accessing /login it automatically redirects to okta login page
get("/login") {
   call.respondRedirect("/")
}
 
```
 
**Authorization endpoint `/login/authorization-callback`**
 
Upon successful authorization, the user will be redirected to this URL. Okta Authorization service provides access and id tokens in the query parameters as part of the login flow. If unsure, [read illustrated guide to OAuth and OIDC](oauth-and-oidc).
To extract information(parse JWT) about the user previously created JwtVerifiers will be used. Then, the user's name will be taken from the token's claims and _"slugified"_, to create a URL-safe alphanumeric username. Finally, a new session is created and the user redirected to the `/`
 
```kotlin
// Okta calls this endpoint providing accessToken along with requested idToken
get("/login/authorization-callback") {
   // Get a principal from from OAuth2 token
   val principal = call.authentication.principal<OAuthAccessTokenResponse.OAuth2>()
       ?: throw Exception("No principal was given")
 
   // Parse and verify access token with OktaJwtVerifier
   val accessToken = accessTokenVerifier.decode(principal.accessToken)
 
   // Get idTokenString, parse and verify id token
   val idTokenString = principal.extraParameters["id_token"]
       ?: throw Exception("id_token wasn't returned")
   val idToken = idVerifier.decode(idTokenString, null)
 
   // Try to get handle from the id token, of failback to subject field in access token
   val fullName = (idToken.claims["name"] ?: accessToken.claims["sub"] ?: "UNKNOWN_NAME").toString()
 
   println("User $fullName logged in successfully")
 
   // Create a session object with "slugified" username 
   val session = UserSession(
       username = fullName.replace("[^a-zA-Z0-9]".toRegex(), ""),
       idToken = idTokenString
   )
 
   call.sessions.set(session)
   call.respondRedirect("/")
}
```
 
**Logout endpoint `/logout`**
 
Users might have reasons to log out from the website; even they could _simply erase cookies_! Some people might consider that a little bit technical. You can help them to do so by resetting session on the server side:
 
```kotlin
// Perform logout by cleaning session
get("/logout") {
   call.sessions.clear<UserSession>()
   call.respondRedirect("/")
}
```
 
**Start your service**
 
Run your application, open browser at `http://localhost:8080` and click **Login** from the top menu bar. You should be presented with an Okta login screen. After you type your credentials you'll be redirected back to the nabl but as a user this time. Try to send some messages!
 
{% img blog/ktor-nano-blogging-service/ktor-app-user-logged-in-highlighted.png alt:"Nano Blogging Service screenshot with logged-in user" width:"803" %}{: .center-image }
 
 
🎉 Congratulations, you just added authorization to your service!
 
## Logout with Okta
 
Did you try to t̶u̶r̶n̶ ̶i̶t̶ ̶o̶f̶f̶,̶ ̶t̶h̶e̶n̶ ̶o̶n̶ ̶a̶g̶a̶i̶n̶ logout and login again? You might observe an unexpected behavior. If you checked **"remember me"** box in the Okta screen, you virtually can't logout, or at least it looks like that.
 
From the user point of view it would be expected to see a login screen inviting to put login/password, not automatically get logged in:
 
{% img blog/ktor-nano-blogging-service/ktor-webapp-can-not-logout-as-expected.gif alt:"Nano Blogging Service can't log out as expected" width:"803" %}{: .center-image }
 
You might ask yourself, why is it done this way? Why does the Authorization server doesn't purge sessions?
 
Say, you're using Facebook instead of Okta as Authorization and IdentityProvider service. Simply put, you want to logout from some website, and that website also destroys your session in Facebook. It doesn't sound nice, does it?
 
If you intend to logout users from Okta as well you'll need to use something called _RP-Initiated Logout_, read more about it [here](rp-initiated-logout). The basic idea is straightforward - after you remove a session inside your app, the user needs to visit a specially formed `logoutUrl` with `idToken` provided as a `GET` parameter. Update your logout handler:
 
```kotlin
// Perform logout by cleaning cookies and start RP-initiated logout
get("/logout") {
   val idToken = call.session?.idToken
 
   call.sessions.clear<UserSession>()
 
   val redirectLogout = when (idToken) {
       null -> "/"
       else -> URLBuilder(oktaConfig.logoutUrl).run {
           parameters.append("post_logout_redirect_uri", "http://localhost:8080")
           parameters.append("id_token_hint", idToken)
           buildString()
       }
   }
 
   call.respondRedirect(redirectLogout)
}
```
 
Restart your application and try to logout. Now application behaves as you'd expect:
 
{% img blog/ktor-nano-blogging-service/ktor-okta-oauth2-ip-initiated-logout.webp alt:"Nano Blogging Service logout behavior as expected" width:"728" %}{: .center-image }
 
 
## Manage Users With Okta
 
Nano Blogging Service is fun when different people can log in! Create additional users from the Okta Developer Console. From the top menu bar click on **Users** and then **Add Person**. You'll be presented with dialog where a new account can be created manually:
 
{% img blog/ktor-nano-blogging-service/okta-add-person.png alt:"Add additional accounts to Okta" width:"857" %}{: .center-image }
 

### Enable Users Self-Sign Up

Okta also provides a self-sign up service. You can enable it by heading to the Okta Developer Console, hover over **Users** top menu item and select **Registration** from the sub-menu. You'll be presented with this single button you need to click to activate that feature:

{% img blog/ktor-nano-blogging-service/enable-okta-user-registrations.png alt:"Enable self-signup with Okta" width:"766" %}{: .center-image }

If desired, tune the default options and save.

Then, try to login to your service, you'll see the **"Sign up"** link:
 
{% img blog/ktor-nano-blogging-service/okta-signup-enabled.png alt:"Sign up with Okta enabled" width:"626" %}{: .center-image }


 
## Learn more about Ktor and Kotlin
 
Congratulations on finishing this tutorial. You built a Ktor-based Nano Blogging Service secured with Auth 2.0.
 
The source code for this tutorial and the examples in it are available on GitHub in the [ruXlab/okta-ktor-nano-blogging-service](project-repository).
 
 
If you liked this post, you might like these others too:
* [What the Heck is OAuth?](/blog/2017/06/21/what-the-heck-is-oauth)
* [Guide to OAuth 2.0 with Spring Security](/blog/2019/03/12/oauth2-spring-security-guide)
* [Deploy Kotlin with Spring Boot at Heroku](okta-spring-boot)
 
 
Make sure to follow us on [Twitter](https://twitter.com/oktadev) and subscribe to our [YouTube Channel](https://youtube.com/c/oktadev) so that you never miss any awesome content!
 
 
[ktor-website]: https://ktor.io/
[ktor-auth-docs]: https://ktor.io/servers/features/authentication/oauth.html
[okta-signup]: https://developer.okta.com/signup/
[okta-spring-boot]: /blog/2020/08/31/spring-boot-heroku
[hocon]: https://github.com/lightbend/config/blob/master/HOCON.md
[kotlin-extension-functions]: https://kotlinlang.org/docs/reference/extensions.html#extension-functions
[kotlin-coroutines]: https://kotlinlang.org/docs/reference/coroutines-overview.html
[okta-jwt-verifier]: https://github.com/okta/okta-jwt-verifier-java
[oauth-and-oidc]: /blog/2019/10/21/illustrated-guide-to-oauth-and-oidc
[rp-initiated-logout]: /blog/2020/03/27/spring-oidc-logout-options?_ga=2.248058690.477517550.1600209050-541198203.1595620094#what-is-rp-initiated-logout
[project-repository]: https://github.com/ruXlab/okta-ktor-nano-blogging-service
[okta-customers]: https://www.okta.com/customers/ 

