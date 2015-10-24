# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import prettytable


class EntityFormatter(object):
    """Base Mixin class providing functions that format entities for display.

    Must be used in conjunction with a Formatter mixin that provides
    the function _get_formatted_data().
    """

    @staticmethod
    def _list_objects(obj_list):
        columns = []
        data = (obj._get_generic_data() for obj in obj_list)
        if obj_list:
            columns = obj_list[0]._get_generic_columns()
        return columns, data

    def _get_generic_data(self):
        return self._get_formatted_data()

    def _get_generic_columns(self):
        return self.columns

    def _get_formatted_entity(self):
        return self.columns, self._get_formatted_data()

    def __str__(self):
        """Provides a common prettytable based format for object strings."""
        data = self._get_formatted_data()
        table = prettytable.PrettyTable(field_names=('Field', 'Value'),
                                        print_empty=False)
        table.padding_width = 1
        table.align['Field'] = 'l'
        table.align['Value'] = 'l'
        for name, value in zip(self.columns, data):
            table.add_row((name, value))
        return table.get_string(fields=('Field', 'Value'))

    def to_dict(self):
        columns, data = self._get_formatted_entity()
        return dict((key, value) for (key, value) in zip(columns, data))
