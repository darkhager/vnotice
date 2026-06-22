export default function Widgets() {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
      <div className="glass-panel p-6 rounded-2xl">
        <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Total CVEs Monitored</h3>
        <p className="text-3xl font-bold mt-2 text-gray-900 dark:text-white">1,248</p>
      </div>
      <div className="glass-panel p-6 rounded-2xl">
        <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Critical Severity</h3>
        <p className="text-3xl font-bold mt-2 text-red-500">142</p>
      </div>
      <div className="glass-panel p-6 rounded-2xl">
        <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Updates Today</h3>
        <p className="text-3xl font-bold mt-2 text-blue-500">24</p>
      </div>
      <div className="glass-panel p-6 rounded-2xl">
        <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Active Alerts</h3>
        <p className="text-3xl font-bold mt-2 text-orange-500">5</p>
      </div>
    </div>
  );
}
