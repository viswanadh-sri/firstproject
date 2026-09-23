import { useEffect, useState } from "react";

const apiBaseUrl = (import.meta.env.VITE_API_URL || "").replace(/\/+$/, "");

export default function withAuth(
  Component,
  {
    redirectTo = "/login",
    apiPath = "/auth/me",
    loadingFallback = null
  } = {}
) {
  function AuthenticatedComponent(props) {
    const [isAuthorized, setIsAuthorized] = useState(null);

    useEffect(() => {
      fetch(`${apiBaseUrl}${apiPath}`, { credentials: "include" })
        .then((response) => {
          if (!response.ok) throw new Error("Not authenticated");
          setIsAuthorized(true);
        })
        .catch(() => setIsAuthorized(false));
    }, [apiPath]);

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
