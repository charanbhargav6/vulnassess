const path = require('path');

process.env.GENERATE_SOURCEMAP = 'false';

const buildScript = path.join(__dirname, '..', 'node_modules', 'react-scripts', 'scripts', 'build.js');
require(buildScript);