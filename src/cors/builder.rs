//! Typed CORS configuration builder

use crate::cors::{
    Cors, CorsError, OrWildcard,
    origin::{Origin, OriginParseError},
};
use rocket::http::Method;
use std::{collections::HashSet, time::Duration};

#[derive(Default)]
struct CorsConfig {
    allow_origin: Option<OrWildcard<HashSet<Origin>>>,
    allow_method: Option<HashSet<Method>>,
    allow_header: Option<OrWildcard<HashSet<String>>>,
    access_max_age: Option<Duration>,
    allow_credentials: bool,
}

/// A builder for the `Cors` fairing. This allows for a more flexible and dynamic way to configure
/// cors headers without having to create a new `Cors` instance every time a configuration change
/// is needed.
#[derive(Default)]
pub struct CorsBuilder<const HAS_ORIGIN: bool> {
    cfg: CorsConfig,
}


// --- Constructor ---
impl CorsBuilder<false> {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}


// --- `with_origin` and similar ---
impl<const HAS_ORIGIN: bool> CorsBuilder<HAS_ORIGIN> {
    /// This will dynamically set the `access-control-allow-origin` header depending on if the
    /// incoming request is coming from a valid origin set by this method. As only 1 origin is
    /// allowed in this header, this must be dynamic to accept more than 1 origin.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_ext::cors::Cors;
    /// let cors = Cors::builder()
    ///     .with_origin("http://test.com")
    ///     .expect("A valid URI")
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_origin(
        self,
        url: impl TryInto<Origin, Error = OriginParseError>,
    ) -> Result<CorsBuilder<true>, CorsError> {
        let Self { mut cfg } = self;
        let mut origins = cfg
            .allow_origin
            .take()
            .unwrap_or_default()
            .take_or_default();
        origins.insert(url.try_into()?);

        cfg.allow_origin = Some(OrWildcard::Explicit(origins));

        Ok(CorsBuilder { cfg })
    }

    /// This will dynamically set the `access-control-allow-origin` header depending on if the
    /// incoming request is coming from a valid origin set by this method. As only 1 origin is
    /// allowed in this header, this must be dynamic to accept more than 1 origin.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_ext::cors::Cors;
    /// let cors = Cors::builder()
    ///     .with_origins(["http://test.com", "https://othertest.com"])
    ///     .expect("A valid URI")
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_origins<T, I>(mut self, urls: I) -> Result<Self, CorsError>
    where
        I: IntoIterator<Item = T>,
        T: TryInto<Origin, Error = OriginParseError>,
    {
        let mut origins = self
            .cfg
            .allow_origin
            .take()
            .unwrap_or_default()
            .take_or_default();

        for url in urls {
            origins.insert(url.try_into()?);
        }
        self.cfg.allow_origin = Some(OrWildcard::Explicit(origins));

        Ok(self)
    }

    /// This will set the `access-control-allow-origin` header to allow any origin. This is
    /// equivalent to setting the header to `*`, which means any origin is allowed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_ext::cors::Cors;
    /// let cors = Cors::builder()
    ///     .with_any_origin()
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_any_origin(self) -> CorsBuilder<false> {
        let Self { mut cfg } = self;
        cfg.allow_origin = Some(OrWildcard::Wildcard);
        CorsBuilder { cfg }
    }
}


// --- `with_method` and similar ---
impl<const HAS_ORIGIN: bool> CorsBuilder<HAS_ORIGIN> {
    /// This will set the `access-control-allow-methods` header to allow the specified HTTP method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_ext::cors::{Cors, Method};
    /// let cors = Cors::builder()
    ///     .with_method(Method::Get)
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_method(mut self, method: Method) -> Self {
        let mut methods = self.cfg.allow_method.take().unwrap_or_default();
        methods.insert(method);
        self.cfg.allow_method = Some(methods);

        self
    }

    /// This will set the `access-control-allow-methods` header to allow the specified HTTP method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_ext::cors::{Cors, Method};
    /// let cors = Cors::builder()
    ///     .with_methods(&[Method::Get, Method::Post])
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_methods(mut self, methods_to_insert: &[Method]) -> Self {
        let mut methods = self.cfg.allow_method.take().unwrap_or_default();
        methods.extend(methods_to_insert);

        self.cfg.allow_method = Some(methods);
        self
    }

}


// --- `with_header` and similar ---
impl<const HAS_ORIGIN: bool> CorsBuilder<HAS_ORIGIN> {
    /// This will set the `access-control-allow-headers` header to allow the specified header.
    ///
    /// # Example
    /// ```
    /// use rocket_ext::cors::Cors;
    /// let cors = Cors::builder()
    ///     .with_header("X-Custom-Header")
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_header(mut self, header_name: impl ToString) -> Self {
        let mut headers = self
            .cfg
            .allow_header
            .take()
            .unwrap_or_default()
            .take_or_default();
        headers.insert(header_name.to_string());

        self.cfg.allow_header = Some(OrWildcard::Explicit(headers));

        self
    }

    /// This will set the `access-control-allow-headers` header to allow the specified header.
    ///
    /// # Example
    /// ```
    /// use rocket_ext::cors::Cors;
    /// use http::header::{ACCEPT,CONTENT_TYPE};
    /// let cors = Cors::builder()
    ///     .with_headers(&["X-Custom-Header", "X-Other-Header"])
    ///     // you may pass an http::header::HeaderName as well
    ///     .with_headers(&[ACCEPT, CONTENT_TYPE])
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_headers(mut self, headers: &[impl ToString]) -> Self {
        let mut header_set = self
            .cfg
            .allow_header
            .take()
            .unwrap_or_default()
            .take_or_default();

        for header in headers {
            header_set.insert(header.to_string());
        }
        self.cfg.allow_header = Some(OrWildcard::Explicit(header_set));

        self
    }

    /// This will set the `access-control-allow-headers` header to allow any header. This is
    /// equivalent to setting the header to `*`, which means any header is allowed. However, in
    /// order to be more explicit, CORS will respond with the headers sent in the request. For
    /// example: if the request contains the headers `X-Custom-Header` and `X-Other-Header`, then
    /// the response will contain the header `Access-Control-Allow-Headers: X-Custom-Header,
    /// X-Other-Header`.
    ///
    /// # Example
    /// ```rust
    /// use rocket_ext::cors::Cors;
    ///
    /// let cors = Cors::builder()
    ///     .with_any_header()
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_any_header(mut self) -> Self {
        self.cfg.allow_header = Some(OrWildcard::Wildcard);
        self
    }
}


// --- `with_max_age` ---
impl<const HAS_ORIGIN: bool> CorsBuilder<HAS_ORIGIN> {
    /// This will set the `access-control-max-age` header to specify how long the results of a
    /// preflight request can be cached.
    ///
    /// # Example
    /// ```rust
    /// use rocket_ext::cors::Cors;
    /// let cors = Cors::builder()
    ///     .with_max_age(std::time::Duration::from_secs(3600))
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.cfg.access_max_age = Some(age);

        self
    }
}


// --- `with_credentials` ---
impl<const HAS_ORIGIN: bool> CorsBuilder<HAS_ORIGIN> {
    /// This will set the `access-control-allow-credentials` header to allow credentials to be
    /// sent. This is only valid if an `access-control-allow-origin` header is also set.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_ext::cors::Cors;
    /// let cors = Cors::builder()
    ///     .allow_credentials()
    ///     .with_origin("https://example.com")
    ///     .expect("A valid URI")
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn allow_credentials(mut self) -> Self {
        self.cfg.allow_credentials = true;
        self
    }
}


// --- Building the configuration ---
impl<const HAS_ORIGIN: bool> CorsBuilder<HAS_ORIGIN> {
    /// This will build the [`Cors`] configuration. If `allow_credentials` is set to true, then
    /// the [`CorsBuilder::with_origin`] must have been called, otherwise an error will be returned.
    ///
    /// See the [official CORS documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS/Errors/CORSNotSupportingCredentials)
    ///
    /// # Example
    /// ```rust
    /// use rocket_ext::cors::{Cors, Method};
    ///
    /// let cors = Cors::builder()
    ///     .allow_credentials()
    ///     .with_origin("https://example.com")
    ///     .expect("A valid URI")
    ///     .with_max_age(std::time::Duration::from_secs(3600))
    ///     .with_header("X-Custom-Header")
    ///     .with_method(Method::Get)
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn build(self) -> Result<Cors, CorsError> {
        // fail if no origin is set and credentials are allowed, or if the origin is set to
        // wildcard
        if self.cfg.allow_credentials
            && (self.cfg.allow_origin.is_none()
                || self.cfg.allow_origin == Some(OrWildcard::Wildcard))
        {
            return Err(CorsError::WithCredentialsMissingOrigin);
        }

        Ok(Cors {
            origins: self.cfg.allow_origin.unwrap_or_default(),
            headers: self.cfg.allow_header.unwrap_or_default(),
            methods: self.cfg.allow_method.unwrap_or_default(),
            max_age: self.cfg.access_max_age,
            allow_creds: self.cfg.allow_credentials,
        })
    }
}
