import React, { createContext, useContext, useState, useEffect } from 'react';

interface AuthContextType {
  token: string | null;
  csrfToken: string | null;
  isAuthenticated: boolean;
  login: (passcode?: string) => Promise<boolean>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

const TOKEN_STORAGE_KEY = 'dhaal_jwt_token';
const CSRF_STORAGE_KEY = 'dhaal_csrf_token';

let memoryToken: string | null =
  typeof window !== 'undefined' ? window.localStorage.getItem(TOKEN_STORAGE_KEY) : null;
let memoryCsrf: string | null =
  typeof window !== 'undefined' ? window.localStorage.getItem(CSRF_STORAGE_KEY) : null;
let bootstrapPromise: Promise<boolean> | null = null;
const nativeFetch: typeof fetch =
  typeof window !== 'undefined' ? window.fetch.bind(window) : fetch;

async function performBootstrapLogin(passcode?: string): Promise<boolean> {
  try {
    const res = await nativeFetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passcode: passcode || 'DHAAL-SESSION-INIT' }),
    });
    if (!res.ok) return false;
    const data = (await res.json()) as { token?: string; csrfToken?: string };
    if (data.token && data.csrfToken) {
      memoryToken = data.token;
      memoryCsrf = data.csrfToken;
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(TOKEN_STORAGE_KEY, data.token);
        window.localStorage.setItem(CSRF_STORAGE_KEY, data.csrfToken);
      }
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

export async function ensureAuthSession(): Promise<boolean> {
  if (memoryToken && memoryCsrf) {
    return true;
  }
  if (!bootstrapPromise) {
    bootstrapPromise = performBootstrapLogin().finally(() => {
      bootstrapPromise = null;
    });
  }
  return bootstrapPromise;
}

export async function apiFetch(
  input: RequestInfo | URL,
  init?: RequestInit
): Promise<Response> {
  const urlStr =
    typeof input === 'string'
      ? input
      : input instanceof URL
      ? input.toString()
      : input.url;

  const isApiCall =
    urlStr.startsWith('/api/') ||
    (typeof window !== 'undefined' &&
      urlStr.startsWith(`${window.location.origin}/api/`));
  const isAuthEndpoint =
    urlStr.includes('/auth/login') || urlStr.includes('/csrf-token');

  if (!isApiCall || isAuthEndpoint) {
    return nativeFetch(input, init);
  }

  await ensureAuthSession();

  const buildHeaders = (): Headers => {
    const headers = new Headers(init?.headers || {});
    if (memoryToken && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${memoryToken}`);
    }
    if (memoryCsrf && !headers.has('X-CSRF-Token')) {
      headers.set('X-CSRF-Token', memoryCsrf);
    }
    return headers;
  };

  let response = await nativeFetch(input, {
    ...init,
    headers: buildHeaders(),
  });

  if (response.status === 401 || response.status === 403) {
    memoryToken = null;
    memoryCsrf = null;
    const refreshed = await performBootstrapLogin();
    if (refreshed) {
      response = await nativeFetch(input, {
        ...init,
        headers: buildHeaders(),
      });
    }
  }

  return response;
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(memoryToken);
  const [csrfToken, setCsrfToken] = useState<string | null>(memoryCsrf);

  useEffect(() => {
    void ensureAuthSession().then((ok) => {
      if (ok) {
        setToken(memoryToken);
        setCsrfToken(memoryCsrf);
      }
    });
  }, []);

  const login = async (passcode?: string): Promise<boolean> => {
    const ok = await performBootstrapLogin(passcode);
    setToken(memoryToken);
    setCsrfToken(memoryCsrf);
    return ok;
  };

  const logout = () => {
    memoryToken = null;
    memoryCsrf = null;
    setToken(null);
    setCsrfToken(null);
    if (typeof window !== 'undefined') {
      window.localStorage.removeItem(TOKEN_STORAGE_KEY);
      window.localStorage.removeItem(CSRF_STORAGE_KEY);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        token,
        csrfToken,
        isAuthenticated: Boolean(token),
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return ctx;
};
