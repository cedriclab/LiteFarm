/*
 *  Copyright 2019, 2020, 2021, 2022 LiteFarm.org
 *  This file is part of LiteFarm.
 *
 *  LiteFarm is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  LiteFarm is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details, see <https://www.gnu.org/licenses/>.
 */

exports.up = async function (knex) {
  await knex.schema.alterTable('showedSpotlight', (t) => {
    t.boolean('notification').defaultTo(false);
    t.timestamp('notification_end').nullable().defaultTo(null);
  });
};

exports.down = async function (knex) {
  await knex.schema.alterTable('showedSpotlight', (t) => {
    t.dropColumn('notification');
    t.dropColumn('notification_end');
  });
};
