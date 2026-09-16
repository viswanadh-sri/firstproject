import { useEffect, useState } from "react";

const DEFAULT_COOKIE_NAMES = ["access_token", "token"];
const DEFAULT_STORAGE_KEYS = ["access_token", "token"];

function hasCookie(name) {
  return document.cookie.split(";").some((cookie) => {
    const [cookieName, ...cookieValue] = cookie.trim().split("=");
    return cookieName === name && cookieValue.join("=") !== "";
  });
}

function hasStoredToken(key) {
  return Boolean(window.localStorage.getItem(key));
}

function hasAuthToken(cookieNames, storageKeys) {
  const cookieToken = cookieNames.some(hasCookie);
  const storageToken = storageKeys.some(hasStoredToken);
  return cookieToken || storageToken;
}

export default function withAuth(
  Component,
  {
    redirectTo = "/login",
    cookieNames = DEFAULT_COOKIE_NAMES,
    storageKeys = DEFAULT_STORAGE_KEYS,
    loadingFallback = null
  } = {}
) {
  function AuthenticatedComponent(props) {
    const [isAuthorized, setIsAuthorized] = useState(null);

    useEffect(() => {
      setIsAuthorized(hasAuthToken(cookieNames, storageKeys));
    }, []);

    useEffect(() => {
      if (isAuthorized === false) {
        window.location.replace(redirectTo);
      }
    }, [isAuthorized, redirectTo]);

    if (isAuthorized !== true) {
      return loadingFallback;
    }

    return <Component {...props} />;
  }

  AuthenticatedComponent.displayName = `withAuth(${Component.displayName || Component.name || "Component"})`;
  return AuthenticatedComponent;
}
