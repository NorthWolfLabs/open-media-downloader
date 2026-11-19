import {execFile} from 'node:child_process';
import {promisify} from 'node:util';

// Cargo owns target-dir resolution, including environment and .cargo config.
export async function cargoTargetDirectory(cwd, env=process.env) {
  const {stdout} = await promisify(execFile)('cargo',
    ['metadata','--no-deps','--locked','--offline','--format-version','1'],
    {cwd, env, timeout:30000, maxBuffer:16*1024*1024});
  const directory=JSON.parse(stdout).target_directory;
  if(typeof directory!=='string'||!directory)throw new Error('Cargo did not report a target directory');
  return directory;
}
