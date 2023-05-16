ActiveRecord::Schema.define(version: 2023_05_14_182527) do

  create_table "fake_users", force: :cascade do |t|
    t.text "name"
    t.text "email"
    t.text "ssn"
  end

end
