require 'rack'
require 'json'

class SampleServer < Rack::Builder
  def self.call(env)
    case env['REQUEST_METHOD']
    when 'GET'
      get_books(env)
    when 'POST'
      create_book(env)
    when 'PUT'
      update_book(env)
    when 'DELETE'
      delete_book(env)
    else
       [404, {'Content-Type' =>  'text/plain'}, ['Not']]
    end
  end

  def self.get_books(env)
     # Return a list of books in JSON format
     [200, {'Content-Type' => 'application/json'}, [{id: 1, title: 'Book 1', author: 'Author 1'}].to_json]
  end

  def self.create_book(env)
     # Create a new book from the request body
    book = JSON.parse(env['rack.input'].read)
     # Simulate creating a new book in a database
     [201, {'Content-Type' => 'application/json'}, [{id: 2, title: book['title'], author: book['author']}.to_json]]
  end

  def self.update_book(env)
     # Update an existing book from the request body
    book = JSON.parse(env['rack.input'].read)
     # Simulate updating a book in a database
     [200, {'Content-Type' => 'application/json'}, [{id: 1, title: book['title'], author: book['author']}.to_json]]
  end

  def self.delete_book(env)
     # Delete an existing book
     # Simulate deleting a book from a database
     [204, {'Content-Type' => 'text/plain'}, ['Book deleted']]
  end
end

# run SampleServer.new