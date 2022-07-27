/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {Query, queryEqual} from './reference';

export class AggregateQuery {

  /** @hideconstructor */
  constructor(query: Query<unknown>) {
    this.query = query;
  }

  readonly type = "AggregateQuery";

  readonly query: Query<unknown>;
}

export class AggregateQuerySnapshot {

  /** @hideconstructor */
  constructor(query: AggregateQuery, readonly _count: number) {
    this.query = query;
  }

  readonly type = "AggregateQuerySnapshot";

  readonly query: AggregateQuery;

  getCount(): number | null {
    return this._count;
  }
}

export function countQuery(query: Query<unknown>): AggregateQuery {
  return new AggregateQuery(query);
}

export function getAggregateFromServerDirect(query: AggregateQuery): Promise<AggregateQuerySnapshot> {
  return Promise.resolve(new AggregateQuerySnapshot(query, 42));
}

export function aggregateQueryEqual(left: AggregateQuery, right: AggregateQuery): boolean {
  return queryEqual(left.query, right.query);
}

export function aggregateQuerySnapshotEqual(left: AggregateQuerySnapshot, right: AggregateQuerySnapshot): boolean {
  return aggregateQueryEqual(left.query, right.query) && left.getCount() === right.getCount();
}
