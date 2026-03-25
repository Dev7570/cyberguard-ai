import '@/styles/globals.css';
import Head from 'next/head';

export default function App({ Component, pageProps }) {
  return (
    <>
      <Head>
        <title>CyberGuard-AI — Network Threat Intelligence</title>
        <meta name="description" content="Real-time network threat detection and intelligence platform powered by machine learning" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="theme-color" content="#070b1a" />
        <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><text y='14' font-size='14'>🛡️</text></svg>" />
      </Head>
      <Component {...pageProps} />
    </>
  );
}
