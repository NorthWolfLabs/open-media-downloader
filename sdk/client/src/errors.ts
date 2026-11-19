import type {Problem} from './models.js';
export class EngineError extends Error {
  constructor(public problem:Problem,public status:number){super(problem.message);}
}
