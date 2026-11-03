export type SearchCategory =
  | "navigation"
  | "action"
  | "target"
  | "assessment"
  | "finding";

export interface SearchResultItem {
  id: string;
  title: string;
  subtitle?: string;
  category: SearchCategory;
  url: string;
  badge?: string;
  shortcut?: string;
  icon?: string;
}

export interface SearchGroup {
  category: SearchCategory;
  title: string;
  items: SearchResultItem[];
}

export interface UseUrlFiltersOptions<T extends Record<string, string | number | boolean | undefined>> {
  defaultValues: T;
}
