/**
 * Worker para verificar certificados SSL y enviar métricas a New Relic
 * Soporta ejecución via HTTP requests y Cron Triggers
 */

export default {
  async fetch(request, env, ctx) {
    // Configurar CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        }
      });
    }

    const url = new URL(request.url);
    
    // Solo permitir GET
    if (request.method !== 'GET') {
      return new Response(JSON.stringify({ 
        error: 'Método no permitido',
        eventType: 'SSL_Certificate_Metrics'
      }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Ruta para verificar SSL
    if (url.pathname === '/check') {
      const domain = url.searchParams.get('domain');
      
      if (!domain) {
        return new Response(
          JSON.stringify({ 
            error: 'Parámetro "domain" requerido',
            eventType: 'SSL_Certificate_Metrics'
          }),
          { 
            status: 400, 
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          }
        );
      }

      try {
        // Obtener información SSL
        const sslData = await getSSLInfo(domain);
        
        // Preparar datos para New Relic
        const newRelicEvent = {
          eventType: 'SSL_Certificate_Metrics',
          domain: domain,
          daysRemaining: sslData.daysRemaining,
          expirationDate: sslData.expirationDate,
          validFrom: sslData.validFrom,
          issuer: sslData.issuer,
          automatedCheck: false // Indica que fue una verificación manual
        };

        // Enviar a New Relic (en segundo plano)
        ctx.waitUntil(sendToNewRelic([newRelicEvent], env));
        
        // Responder al cliente
        return new Response(
          JSON.stringify(newRelicEvent),
          { 
            status: 200,
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          }
        );
        
      } catch (err) {
        // Registrar error en New Relic también
        const errorEvent = {
          eventType: 'SSL_Certificate_Error',
          domain: domain,
          error: err.message,
          timestamp: Date.now(),
          automatedCheck: false
        };
        ctx.waitUntil(sendToNewRelic([errorEvent], env));
        
        return new Response(
          JSON.stringify({ 
            eventType: 'SSL_Certificate_Metrics',
            error: err.message,
            domain: domain,
            ...(url.hostname === 'localhost' && { stack: err.stack })
          }),
          { 
            status: 500,
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          }
        );
      }
    }

    // Ruta raíz - información de uso
    return new Response(
      JSON.stringify({
        eventType: 'SSL_Certificate_Metrics',
        service: 'SSL Certificate Monitor',
        usage: 'GET /check?domain=example.com',
        note: 'Los datos se envían automáticamente a New Relic',
        cronSupport: 'Este worker también soporta ejecución programada via Cron Triggers',
        example: `curl "${url.origin}/check?domain=cloudflare.com"`
      }),
      { 
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      }
    );
  },

  // Handler para ejecución programada via Cron
  async scheduled(event, env, ctx) {
    // Lista de dominios a verificar
    const domainsToCheck = [
      'www.google.com',
      'www.cloudflare.com',
      'ssl.com'
    ];

    // Si tienes muchos dominios, considera usar Cloudflare KV
    // const domainsToCheck = await env.SSL_DOMAINS_KV.get('domains', { type: 'json' }) || [];

    console.log(`Iniciando verificación programada para ${domainsToCheck.length} dominios`);

    // Procesar cada dominio en paralelo
    const results = await Promise.allSettled(
      domainsToCheck.map(domain => 
        checkAndReportDomain(domain, env, ctx)
      )
    );

    // Resumen de resultados
    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;
    
    // Registrar resumen en New Relic
    const summaryEvent = {
      eventType: 'SSL_Certificate_Cron_Summary',
      totalDomains: domainsToCheck.length,
      successfulChecks: successful,
      failedChecks: failed,
      timestamp: new Date().toISOString()
    };
    
    ctx.waitUntil(sendToNewRelic([summaryEvent], env));
    
    console.log(`Verificación programada completada: ${successful} exitosas, ${failed} fallidas`);
  }
};

/**
 * Función auxiliar para verificar un dominio y reportar a New Relic
 */
async function checkAndReportDomain(domain, env, ctx) {
  try {
    const sslData = await getSSLInfo(domain);
    
    const newRelicEvent = {
      eventType: 'SSL_Certificate_Metrics',
      domain: domain,
      daysRemaining: sslData.daysRemaining,
      expirationDate: sslData.expirationDate,
      validFrom: sslData.validFrom,
      issuer: sslData.issuer,
      automatedCheck: true // Indica que fue una verificación automática
    };

    await sendToNewRelic([newRelicEvent], env);
    return { success: true, domain };
  } catch (err) {
    const errorEvent = {
      eventType: 'SSL_Certificate_Error',
      domain: domain,
      error: err.message,
      timestamp: Date.now(),
      automatedCheck: true
    };
    await sendToNewRelic([errorEvent], env);
    
    // También registrar el error en los logs del Worker
    console.error(`Error verificando ${domain}:`, err.message);
    
    throw { success: false, domain, error: err.message };
  }
}

/**
 * Obtiene información SSL del dominio
 */
async function getSSLInfo(domain) {
  const cleanedDomain = cleanHostname(domain);
  
  // Consultar crt.sh API
  const apiUrl = `https://crt.sh/?q=${encodeURIComponent(cleanedDomain)}&output=json`;
  
  const response = await fetch(apiUrl, {
    headers: {
      'User-Agent': 'Cloudflare-Workers-SSL-Checker/1.0'
    }
  });
  
  if (!response.ok) {
    throw new Error(`Error al consultar crt.sh: ${response.status}`);
  }
  
  const certificates = await response.json();
  
  if (!Array.isArray(certificates)) {
    throw new Error('Formato de respuesta inesperado');
  }
  
  if (certificates.length === 0) {
    throw new Error('No se encontraron certificados');
  }
  
  // Filtrar certificados con fechas válidas
  const validCerts = certificates.filter(cert => cert.not_after && cert.not_before);
  if (validCerts.length === 0) {
    throw new Error('No se encontraron certificados válidos');
  }
  
  // Ordenar por fecha de expiración (más reciente primero)
  validCerts.sort((a, b) => new Date(b.not_after) - new Date(a.not_after));
  const latestCert = validCerts[0];
  
  // Calcular días restantes
  const validTo = new Date(latestCert.not_after);
  const today = new Date();
  const diffTime = validTo - today;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  
  return {
    daysRemaining: diffDays,
    expirationDate: latestCert.not_after,
    validFrom: latestCert.not_before,
    issuer: latestCert.issuer_name || 'Unknown'
  };
}

/**
 * Limpia el hostname
 */
function cleanHostname(hostname) {
  return hostname
    .replace(/^(https?:\/\/)?/, '')
    .split('/')[0]
    .split(':')[0]
    .replace(/^\*\./, '');
}

/**
 * Envía datos a New Relic
 * @param {Array} data - Datos a enviar
 * @param {Object} env - Variables de entorno
 */
async function sendToNewRelic(data, env) {
  try {
    // Validar que tenemos las credenciales necesarias
    if (!env.NEW_RELIC_ACCOUNT_ID || !env.NEW_RELIC_API_KEY) {
      console.error('Missing New Relic credentials');
      return;
    }

    const newRelicUrl = `https://insights-collector.newrelic.com/v1/accounts/${env.NEW_RELIC_ACCOUNT_ID}/events`;
    
    const response = await fetch(newRelicUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Api-Key': env.NEW_RELIC_API_KEY
      },
      body: JSON.stringify(data)
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error(`New Relic API error: ${response.status} - ${errorBody}`);
      throw new Error(`New Relic API error: ${response.status}`);
    }
    
    return response;
  } catch (error) {
    console.error('Error sending to New Relic:', error);
    throw error;
  }
}