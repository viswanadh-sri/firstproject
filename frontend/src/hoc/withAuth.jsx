import { useEffect, useState } from "react";

export default function withAuth(
  Component,
  {
    redirectTo = "/login",
    apiUrl = "/auth/me",
    loadingFallback = null
  } = {}
) {
  function AuthenticatedComponent(props) {
    const [isAuthorized, setIsAuthorized] = useState(null);

    useEffect(() => {
      fetch(apiUrl, { credentials: "include" })
        .then((response) => {
          if (!response.ok) throw new Error("Not authenticated");
          setIsAuthorized(true);
        })
        .catch(() => setIsAuthorized(false));
    }, [apiUrl]);

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
