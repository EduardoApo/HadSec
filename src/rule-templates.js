export const sampleSQL=`SELECT
    srcIpAddr,
    user,
    COUNT(*) AS attempts
FROM fsiem.events
WHERE phRecvTime > (now() - 300)
    AND eventType = 'Win-Security-4625'
GROUP BY srcIpAddr, user
HAVING COUNT(*) >= 10
LIMIT 100`;
